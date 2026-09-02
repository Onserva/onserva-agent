package dbstat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// A minimal MySQL/MariaDB text-protocol client, the same bargain as pg.go:
// ~250 auditable lines instead of a dependency tree. It authenticates with an
// EMPTY credential only — which is what unix_socket / auth_socket plugins
// expect, because the proof is the kernel-verified identity of the connecting
// user, not anything sent on the wire. A server that wants an actual password
// gets nothing to work with and the engine is reported not-connectable.

const (
	clientProtocol41       = 0x00000200
	clientSecureConnection = 0x00008000
	clientPluginAuth       = 0x00080000
)

type mysqlConn struct {
	conn net.Conn
	seq  uint8
}

func probeMySQL(socket string) bool {
	c, err := mysqlConnect(socket)
	if err != nil {
		return false
	}
	defer c.close()
	_, err = c.query("SELECT 1")
	return err == nil
}

func mysqlConnect(socket string) (*mysqlConn, error) {
	conn, err := net.DialTimeout("unix", socket, probeTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	c := &mysqlConn{conn: conn}
	if err := c.handshake(); err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

func (c *mysqlConn) close() { _ = c.conn.Close() }

func (c *mysqlConn) handshake() error {
	payload, err := c.readPacket()
	if err != nil {
		return err
	}
	if len(payload) > 0 && payload[0] == 0xff {
		return errors.New(mysqlErrorMessage(payload))
	}
	if len(payload) < 1 || payload[0] != 10 {
		return errors.New("unsupported handshake protocol")
	}

	// Server version and connection id are read past; the auth plugin name at
	// the tail is echoed back so the server goes straight to the plugin it
	// wanted instead of a needless auth-switch round trip.
	rest := payload[1:]
	if i := indexByte(rest, 0); i < 0 {
		return errors.New("malformed handshake")
	} else {
		rest = rest[i+1:]
	}
	if len(rest) < 4+8+1+2 {
		return errors.New("short handshake")
	}
	rest = rest[4+8+1+2:] // connection id, auth-data-1, filler, capability low

	plugin := ""
	if len(rest) >= 1+2+2+1+10 {
		authLen := int(rest[5])
		rest = rest[1+2+2+1+10:] // charset, status, capability high, auth len, reserved
		// Auth plugin data part 2: max(13, authLen-8) bytes, not needed for an
		// empty credential.
		if tail := max(13, authLen-8); len(rest) >= tail {
			rest = rest[tail:]
			if i := indexByte(rest, 0); i >= 0 {
				plugin = string(rest[:i])
			}
		}
	}
	if plugin == "" {
		plugin = "mysql_native_password"
	}

	// HandshakeResponse41 with an empty auth response.
	var body []byte
	body = binary.LittleEndian.AppendUint32(body,
		clientProtocol41|clientSecureConnection|clientPluginAuth)
	body = binary.LittleEndian.AppendUint32(body, 1<<24) // max packet
	body = append(body, 33)                              // utf8_general_ci
	body = append(body, make([]byte, 23)...)
	body = append(body, currentUsername()...)
	body = append(body, 0)
	body = append(body, 0) // auth response length: empty
	body = append(body, plugin...)
	body = append(body, 0)
	if err := c.writePacket(body); err != nil {
		return err
	}

	for {
		payload, err := c.readPacket()
		if err != nil {
			return err
		}
		switch {
		case len(payload) > 0 && payload[0] == 0x00:
			return nil // OK
		case len(payload) > 0 && payload[0] == 0xff:
			return errors.New(mysqlErrorMessage(payload))
		case len(payload) > 0 && payload[0] == 0xfe:
			// AuthSwitchRequest. Whatever plugin it names, the only answer this
			// client has is the empty one — correct for unix_socket/auth_socket,
			// and a clean refusal for everything password-shaped.
			if err := c.writePacket(nil); err != nil {
				return err
			}
		case len(payload) > 0 && payload[0] == 0x01:
			// AuthMoreData (caching_sha2). An empty password needs nothing
			// more; keep reading for the verdict.
		default:
			return errors.New("unexpected authentication reply")
		}
	}
}

// query runs one statement and returns the rows of its (single) result set as
// text, nulls as "".
func (c *mysqlConn) query(sql string) ([][]string, error) {
	_ = c.conn.SetDeadline(time.Now().Add(probeTimeout))
	c.seq = 0
	if err := c.writePacket(append([]byte{0x03}, sql...)); err != nil {
		return nil, err
	}

	first, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	switch {
	case len(first) > 0 && first[0] == 0xff:
		return nil, errors.New(mysqlErrorMessage(first))
	case len(first) > 0 && first[0] == 0x00:
		return nil, nil // OK packet: statement produced no result set
	}

	columns, _, err := readLenencUint(first)
	if err != nil {
		return nil, err
	}

	// Column definitions, then their terminating EOF. (This client never sets
	// CLIENT_DEPRECATE_EOF, so the EOF packets are always there to read.)
	for i := uint64(0); i <= columns; i++ {
		payload, err := c.readPacket()
		if err != nil {
			return nil, err
		}
		if isEOF(payload) {
			break
		}
	}

	var rows [][]string
	for {
		payload, err := c.readPacket()
		if err != nil {
			return nil, err
		}
		if isEOF(payload) {
			return rows, nil
		}
		if len(payload) > 0 && payload[0] == 0xff {
			return nil, errors.New(mysqlErrorMessage(payload))
		}
		row, err := parseMySQLTextRow(payload, int(columns))
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
}

func isEOF(payload []byte) bool {
	return len(payload) > 0 && payload[0] == 0xfe && len(payload) < 9
}

func parseMySQLTextRow(payload []byte, columns int) ([]string, error) {
	row := make([]string, 0, columns)
	rest := payload
	for i := 0; i < columns; i++ {
		if len(rest) == 0 {
			return nil, errors.New("truncated row")
		}
		if rest[0] == 0xfb { // NULL
			row = append(row, "")
			rest = rest[1:]
			continue
		}
		length, consumed, err := readLenencUint(rest)
		if err != nil {
			return nil, err
		}
		rest = rest[consumed:]
		if uint64(len(rest)) < length {
			return nil, errors.New("truncated row value")
		}
		row = append(row, string(rest[:length]))
		rest = rest[length:]
	}
	return row, nil
}

func readLenencUint(b []byte) (value uint64, consumed int, err error) {
	if len(b) == 0 {
		return 0, 0, errors.New("empty length-encoded integer")
	}
	switch {
	case b[0] < 0xfb:
		return uint64(b[0]), 1, nil
	case b[0] == 0xfc && len(b) >= 3:
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3, nil
	case b[0] == 0xfd && len(b) >= 4:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, nil
	case b[0] == 0xfe && len(b) >= 9:
		return binary.LittleEndian.Uint64(b[1:9]), 9, nil
	}
	return 0, 0, errors.New("malformed length-encoded integer")
}

func mysqlErrorMessage(payload []byte) string {
	// 0xff, 2-byte code, then (protocol 4.1) '#' + 5-byte sql state, message.
	rest := payload[1:]
	if len(rest) >= 2 {
		rest = rest[2:]
	}
	if len(rest) >= 6 && rest[0] == '#' {
		rest = rest[6:]
	}
	if len(rest) == 0 {
		return "the database refused the request"
	}
	return string(rest)
}

func (c *mysqlConn) readPacket() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return nil, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length > 1<<20 {
		return nil, fmt.Errorf("implausible packet length %d", length)
	}
	c.seq = header[3] + 1
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (c *mysqlConn) writePacket(payload []byte) error {
	header := []byte{
		byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), c.seq,
	}
	c.seq++
	_, err := c.conn.Write(append(header, payload...))
	return err
}

func indexByte(b []byte, target byte) int {
	for i, v := range b {
		if v == target {
			return i
		}
	}
	return -1
}

// mysqlCounters are the cumulative statistics a rate is derived from.
type mysqlCounters struct {
	questions uint64 // every statement the server has answered
	poolReq   uint64 // buffer pool read requests (logical reads)
	poolRead  uint64 // buffer pool reads that had to touch disk
}

type mysqlDeep struct {
	connections    int
	maxConnections int
	counters       mysqlCounters
	longestQueryS  float64 // -1 when the role may not look
}

// deepMySQL reads the global counters in one authenticated session. The
// PROCESS privilege is all it needs — deliberately no SELECT on any schema,
// so the monitoring role can see how busy the engine is and not one row of
// anyone's data. (That is also why there is no size figure for MySQL: asking
// information_schema for table sizes needs privileges on the tables, and a
// monitoring role that can read your tables is not a monitoring role.)
func deepMySQL(socket string) (*mysqlDeep, error) {
	c, err := mysqlConnect(socket)
	if err != nil {
		return nil, err
	}
	defer c.close()

	deep := &mysqlDeep{longestQueryS: -1}

	rows, err := c.query(
		"SHOW GLOBAL STATUS WHERE Variable_name IN" +
			" ('Threads_connected','Questions'," +
			"'Innodb_buffer_pool_read_requests','Innodb_buffer_pool_reads')")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if len(row) != 2 {
			continue
		}
		switch row[0] {
		case "Threads_connected":
			deep.connections = atoiOr(row[1], 0)
		case "Questions":
			deep.counters.questions = uintOr(row[1])
		case "Innodb_buffer_pool_read_requests":
			deep.counters.poolReq = uintOr(row[1])
		case "Innodb_buffer_pool_reads":
			deep.counters.poolRead = uintOr(row[1])
		}
	}

	rows, err = c.query("SHOW GLOBAL VARIABLES WHERE Variable_name = 'max_connections'")
	if err != nil {
		return nil, err
	}
	if len(rows) == 1 && len(rows[0]) == 2 {
		deep.maxConnections = atoiOr(rows[0][1], 0)
	}

	if rows, err = c.query(
		"SELECT COALESCE(MAX(time), 0) FROM information_schema.processlist" +
			" WHERE command <> 'Sleep' AND id <> CONNECTION_ID()"); err == nil &&
		len(rows) == 1 && len(rows[0]) == 1 {
		deep.longestQueryS = floatOr(rows[0][0])
	}

	return deep, nil
}
