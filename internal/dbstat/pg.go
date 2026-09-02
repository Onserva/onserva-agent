package dbstat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/user"
	"strconv"
	"time"
)

// A minimal PostgreSQL simple-query client — the whole of it, on purpose.
//
// The agent ships with no third-party code because it runs on machines we do
// not own, so the alternative to these ~200 lines is a dependency tree nobody
// can checksum. It speaks exactly the subset the statistics queries need:
// startup over a unix socket, PEER AUTHENTICATION ONLY, simple Query, text
// results. If the server asks for any password scheme the connection is
// closed and the engine reported not-connectable — this client does not know
// what a password is, which is the security property, not a limitation.

// pgConn is one authenticated session.
type pgConn struct {
	conn net.Conn
}

func probePostgres(socket string) bool {
	c, err := pgConnect(socket)
	if err != nil {
		return false
	}
	defer c.close()
	// One trivial round trip, so "connectable" means "answers questions",
	// not merely "accepted the handshake".
	_, err = c.query("select 1")
	return err == nil
}

func pgConnect(socket string) (*pgConn, error) {
	conn, err := net.DialTimeout("unix", socket, probeTimeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	c := &pgConn{conn: conn}
	if err := c.startup(); err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

func (c *pgConn) close() { _ = c.conn.Close() }

// startup sends the version-3 startup message and reads to ReadyForQuery.
// Peer auth over a unix socket answers AuthenticationOk immediately; anything
// else the server asks for is a refusal from our side.
func (c *pgConn) startup() error {
	username := currentUsername()

	var body []byte
	body = binary.BigEndian.AppendUint32(body, 196608) // protocol 3.0
	body = append(body, "user\x00"...)
	body = append(body, username...)
	body = append(body, 0)
	// The postgres database always exists and the statistics views are
	// cluster-wide, so no engine-specific configuration is needed.
	body = append(body, "database\x00postgres\x00"...)
	body = append(body, 0)

	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)+4))
	frame = append(frame, body...)
	if _, err := c.conn.Write(frame); err != nil {
		return err
	}

	for {
		kind, payload, err := c.readMessage()
		if err != nil {
			return err
		}
		switch kind {
		case 'R':
			if len(payload) < 4 {
				return errors.New("short authentication message")
			}
			if authType := binary.BigEndian.Uint32(payload[:4]); authType != 0 {
				// 3 = cleartext, 5 = md5, 10 = SASL… all the same answer:
				// this client holds no secrets to offer.
				return fmt.Errorf("server asked for password authentication (type %d); peer auth is the only kind this agent does", authType)
			}
		case 'E':
			return errors.New(pgErrorMessage(payload))
		case 'Z':
			return nil
		default:
			// ParameterStatus, BackendKeyData, notices — read past.
		}
	}
}

// query runs one statement and returns its rows as text, nulls as "".
func (c *pgConn) query(sql string) ([][]string, error) {
	_ = c.conn.SetDeadline(time.Now().Add(probeTimeout))

	frame := []byte{'Q'}
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(sql)+1+4))
	frame = append(frame, sql...)
	frame = append(frame, 0)
	if _, err := c.conn.Write(frame); err != nil {
		return nil, err
	}

	var rows [][]string
	var queryErr error
	for {
		kind, payload, err := c.readMessage()
		if err != nil {
			return nil, err
		}
		switch kind {
		case 'D':
			row, err := parsePgDataRow(payload)
			if err != nil {
				queryErr = err
			} else {
				rows = append(rows, row)
			}
		case 'E':
			// Remember the error but keep reading: the server still sends
			// ReadyForQuery, and leaving it unread would desynchronise the
			// next query on this connection.
			queryErr = errors.New(pgErrorMessage(payload))
		case 'Z':
			if queryErr != nil {
				return nil, queryErr
			}
			return rows, nil
		default:
			// RowDescription, CommandComplete, notices — read past.
		}
	}
}

func (c *pgConn) readMessage() (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:5])
	if length < 4 || length > 1<<20 {
		return 0, nil, fmt.Errorf("implausible message length %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

func parsePgDataRow(payload []byte) ([]string, error) {
	if len(payload) < 2 {
		return nil, errors.New("short data row")
	}
	count := int(binary.BigEndian.Uint16(payload[:2]))
	fields := make([]string, 0, count)
	rest := payload[2:]
	for i := 0; i < count; i++ {
		if len(rest) < 4 {
			return nil, errors.New("truncated data row")
		}
		size := int(int32(binary.BigEndian.Uint32(rest[:4])))
		rest = rest[4:]
		if size < 0 {
			fields = append(fields, "") // SQL null
			continue
		}
		if len(rest) < size {
			return nil, errors.New("truncated data row value")
		}
		fields = append(fields, string(rest[:size]))
		rest = rest[size:]
	}
	return fields, nil
}

// pgErrorMessage pulls the human-readable field out of an ErrorResponse.
func pgErrorMessage(payload []byte) string {
	rest := payload
	for len(rest) > 0 && rest[0] != 0 {
		code := rest[0]
		rest = rest[1:]
		end := 0
		for end < len(rest) && rest[end] != 0 {
			end++
		}
		if code == 'M' {
			return string(rest[:end])
		}
		if end+1 > len(rest) {
			break
		}
		rest = rest[end+1:]
	}
	return "the database refused the request"
}

// pgCounters are the cumulative statistics a rate is later derived from.
type pgCounters struct {
	xacts    uint64 // commits + rollbacks — "transactions the server carried out"
	blksHit  uint64
	blksRead uint64
}

// pgDeep is one visit to the statistics views.
type pgDeep struct {
	connections    int
	maxConnections int
	counters       pgCounters
	sizeMB         float64 // -1 when the role may not ask
	longestQueryS  float64 // -1 when unknown
}

// deepPostgres reads the cluster-wide statistics in one authenticated session.
// The essentials must all succeed; size and longest-query are separate
// privileges on some setups, so each degrades to absent on its own.
func deepPostgres(socket string) (*pgDeep, error) {
	c, err := pgConnect(socket)
	if err != nil {
		return nil, err
	}
	defer c.close()

	deep := &pgDeep{sizeMB: -1, longestQueryS: -1}

	rows, err := c.query(
		"select count(*), current_setting('max_connections') from pg_stat_activity")
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || len(rows[0]) != 2 {
		return nil, errors.New("unexpected pg_stat_activity shape")
	}
	deep.connections = atoiOr(rows[0][0], 0)
	deep.maxConnections = atoiOr(rows[0][1], 0)

	rows, err = c.query(
		"select coalesce(sum(xact_commit + xact_rollback), 0)," +
			" coalesce(sum(blks_hit), 0), coalesce(sum(blks_read), 0)" +
			" from pg_stat_database")
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || len(rows[0]) != 3 {
		return nil, errors.New("unexpected pg_stat_database shape")
	}
	deep.counters = pgCounters{
		xacts:    uintOr(rows[0][0]),
		blksHit:  uintOr(rows[0][1]),
		blksRead: uintOr(rows[0][2]),
	}

	if rows, err = c.query(
		"select coalesce(sum(pg_database_size(datname)), 0) from pg_database"); err == nil &&
		len(rows) == 1 && len(rows[0]) == 1 {
		deep.sizeMB = float64(uintOr(rows[0][0])) / (1024 * 1024)
	}

	if rows, err = c.query(
		"select coalesce(max(extract(epoch from clock_timestamp() - query_start)), 0)" +
			" from pg_stat_activity where state = 'active' and pid <> pg_backend_pid()"); err == nil &&
		len(rows) == 1 && len(rows[0]) == 1 {
		deep.longestQueryS = floatOr(rows[0][0])
	}

	return deep, nil
}

func currentUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	// The user the agent is installed to run as; only reached if the passwd
	// lookup itself fails.
	return "onserva"
}

func atoiOr(s string, fallback int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

func uintOr(s string) uint64 {
	// Sums arrive as integers; a fractional value would be a schema surprise
	// and parses as 0, which the rate logic treats as a counter reset.
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func floatOr(s string) float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return v
}
