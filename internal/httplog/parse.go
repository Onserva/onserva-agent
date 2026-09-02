package httplog

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Format is how the reverse proxy writes its access log.
type Format string

const (
	// FormatAuto decides per line: JSON if it starts with '{', otherwise CLF.
	// A log can change format mid-file if the proxy is reconfigured and
	// restarted, so this is decided per line rather than once.
	FormatAuto Format = "auto"
	FormatJSON Format = "json"
	FormatCLF  Format = "clf"
)

// entry is the only part of a request we care about. Everything else in the
// line — the path, the client address, the user agent — is deliberately
// discarded here and never leaves the machine.
//
// host was added on 2026-08-13, by the owner's explicit decision that the
// hostnames of their own sites may leave the box. It is the name of the SITE
// the request was for — one of a handful of values the owner chose when they
// configured their proxy — never anything about the visitor. The incident that
// prompted it: one site being crawled into the ground while the dashboard
// could only say "this server is slow", and naming the site took an SSH
// session that the whole product exists to spare people.
type entry struct {
	statusCode int
	durationMs float64
	// Normalised (lowercase, no port), or "" when the log format does not
	// carry it — CLF has no Host field, and "" means "aggregate only", never
	// a made-up site.
	host string
}

// traefikJSON is the subset of Traefik's JSON access log we read.
type traefikJSON struct {
	// Nanoseconds, per Traefik.
	Duration int64 `json:"Duration"`
	// What the client actually received. OriginStatus is what the backend
	// returned, which differs when Traefik itself produces the response —
	// a 502 from a dead backend is a downstream 502 with no origin status at
	// all, and that is precisely the case we must not miss.
	DownstreamStatus int `json:"DownstreamStatus"`
	OriginStatus     int `json:"OriginStatus"`
	// Which site the request was for. The owner's own domain, not visitor data.
	RequestHost string `json:"RequestHost"`
}

// parseLine turns one access-log line into an entry.
// Returns ok=false for blank lines, headers, and anything unrecognisable —
// a malformed line is skipped, never fatal. An access log is written by
// software we do not control and will contain surprises.
func parseLine(line []byte, format Format) (entry, bool) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return entry{}, false
	}

	switch format {
	case FormatJSON:
		return parseJSONLine(trimmed)
	case FormatCLF:
		return parseCLFLine(trimmed)
	default:
		if strings.HasPrefix(trimmed, "{") {
			return parseJSONLine(trimmed)
		}
		return parseCLFLine(trimmed)
	}
}

func parseJSONLine(line string) (entry, bool) {
	var decoded traefikJSON
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		return entry{}, false
	}

	status := decoded.DownstreamStatus
	if status == 0 {
		status = decoded.OriginStatus
	}
	if status == 0 || decoded.Duration < 0 {
		return entry{}, false
	}

	return entry{
		statusCode: status,
		durationMs: float64(decoded.Duration) / 1e6, // ns -> ms
		host:       normalizeHost(decoded.RequestHost),
	}, true
}

// normalizeHost turns whatever arrived in the Host header into a site name we
// are willing to report, or "" for anything else.
//
// The Host header is CLIENT input: scanners send garbage, injections and
// absurd lengths in it all day. So this is an allowlist of what a hostname can
// be — lowercase letters, digits, dots, hyphens (plus underscore, which
// internal names use) — rather than an attempt to strip badness out. Anything
// that fails is counted in the aggregate numbers and attributed to no site,
// which is also where a scanner's nonsense belongs: buckets keyed by attacker
// input would let anyone with curl grow the payload.
func normalizeHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	// Strip a port. IPv6 literals ([::1]:443) contain colons of their own, so
	// only the part after the LAST colon is a candidate port.
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i+1:], "]") {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")

	if host == "" || len(host) > 100 {
		return ""
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == ':':
			// ':' survives only inside a bracket-stripped IPv6 literal.
		default:
			return ""
		}
	}
	return host
}

// parseCLFLine reads Traefik's "common" format:
//
//	10.0.0.1 - - [11/Aug/2026:12:00:00 +0000] "GET /p HTTP/2.0" 200 1234 "-" "-" 42 "router@docker" "http://172.18.0.5:3000" 15ms
//
// The status is the first field after the quoted request; the duration is the
// last field, carrying its own unit suffix.
func parseCLFLine(line string) (entry, bool) {
	start := strings.IndexByte(line, '"')
	if start < 0 {
		return entry{}, false
	}
	end := strings.IndexByte(line[start+1:], '"')
	if end < 0 {
		return entry{}, false
	}

	rest := strings.Fields(line[start+1+end+1:])
	if len(rest) < 2 {
		return entry{}, false
	}

	status, err := strconv.Atoi(rest[0])
	if err != nil || status < 100 || status > 599 {
		return entry{}, false
	}

	durationMs, ok := parseDuration(rest[len(rest)-1])
	if !ok {
		return entry{}, false
	}

	return entry{statusCode: status, durationMs: durationMs}, true
}

// ParseSockstat reads the TCP line of /proc/net/sockstat:
//
//	TCP: inuse 12 orphan 6 tw 2 alloc 384 mem 18
//
// Note where the pairs start. Field 0 is the "TCP:" label, so the key/value
// pairs begin at index 1 — starting at 0 pairs the label with "inuse" and every
// pair after it is off by one, so nothing ever matches and the metric silently
// reports as unmeasured. That is exactly what shipped, and it took real data
// from a real server to notice.
//
// Exported so it can be tested against the genuine article without a /proc.
func ParseSockstat(content string) (inuse int, timeWait int, found bool) {
	inuse, timeWait = -1, -1

	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "TCP:") && !strings.HasPrefix(line, "TCP6:") {
			continue
		}
		fields := strings.Fields(line)
		for i := 1; i+1 < len(fields); i += 2 {
			value, err := strconv.Atoi(fields[i+1])
			if err != nil {
				continue
			}
			switch fields[i] {
			case "inuse": // established plus listening
				inuse = maxInt(inuse, 0) + value
				found = true
			case "tw":
				timeWait = maxInt(timeWait, 0) + value
				found = true
			}
		}
	}
	return inuse, timeWait, found
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// parseDuration reads "15ms", "1.2s", "900µs" and friends into milliseconds.
func parseDuration(field string) (float64, bool) {
	units := []struct {
		suffix string
		toMs   float64
	}{
		{"ms", 1},
		{"µs", 0.001},
		{"us", 0.001},
		{"ns", 0.000001},
		{"s", 1000},
	}

	for _, unit := range units {
		if !strings.HasSuffix(field, unit.suffix) {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSuffix(field, unit.suffix), 64)
		if err != nil || value < 0 {
			return 0, false
		}
		return value * unit.toMs, true
	}

	// No suffix at all: some configurations log plain milliseconds.
	value, err := strconv.ParseFloat(field, 64)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}
