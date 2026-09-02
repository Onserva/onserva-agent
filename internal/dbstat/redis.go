package dbstat

import (
	"bufio"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// A minimal Redis client. RESP is small enough that this is barely a client
// at all: inline commands out, one bulk-string reply in.
//
// No AUTH is ever sent — a Redis with requirepass set answers -NOAUTH and is
// reported not-connectable, which is honest: the agent holds no credentials,
// for Redis exactly as for everything else. (Unix-socket Redis without a
// password is protected by the socket's own file permissions, which is the
// owner's grant, same as an access log's.)

func probeRedis(socket string) bool {
	conn, err := net.DialTimeout("unix", socket, probeTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return false
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	return err == nil && strings.HasPrefix(line, "+PONG")
}

// redisCounters are cumulative; rates come from two visits.
type redisCounters struct {
	commands uint64
	hits     uint64
	misses   uint64
}

type redisDeep struct {
	connections int
	usedMemMB   float64
	counters    redisCounters
}

// deepRedis reads INFO and keeps five numbers from it. Everything else in the
// reply — including anything that could identify a key or a client — is
// discarded here on the machine, the access-log rule applied to Redis.
func deepRedis(socket string) (*redisDeep, error) {
	conn, err := net.DialTimeout("unix", socket, probeTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))

	if _, err := conn.Write([]byte("INFO\r\n")); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	header, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "$") {
		return nil, errors.New(strings.TrimPrefix(header, "-"))
	}
	size, err := strconv.Atoi(header[1:])
	if err != nil || size < 0 || size > 1<<20 {
		return nil, errors.New("implausible INFO reply")
	}
	body := make([]byte, size)
	if _, err := readFull(reader, body); err != nil {
		return nil, err
	}

	deep := &redisDeep{}
	for _, line := range strings.Split(string(body), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch key {
		case "connected_clients":
			deep.connections = atoiOr(value, 0)
		case "used_memory":
			deep.usedMemMB = float64(uintOr(value)) / (1024 * 1024)
		case "total_commands_processed":
			deep.counters.commands = uintOr(value)
		case "keyspace_hits":
			deep.counters.hits = uintOr(value)
		case "keyspace_misses":
			deep.counters.misses = uintOr(value)
		}
	}
	return deep, nil
}

func readFull(reader *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := reader.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
