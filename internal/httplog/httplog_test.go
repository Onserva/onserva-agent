package httplog

import "testing"

// ─── Parsing ────────────────────────────────────────────────────────────────

func TestParseJSONLine(t *testing.T) {
	line := `{"ClientAddr":"10.0.0.1:5000","RequestPath":"/checkout","Duration":152000000,` +
		`"OriginStatus":200,"DownstreamStatus":200,"RequestMethod":"GET"}`

	got, ok := parseLine([]byte(line), FormatJSON)
	if !ok {
		t.Fatal("expected the line to parse")
	}
	if got.statusCode != 200 {
		t.Errorf("status = %d, want 200", got.statusCode)
	}
	if got.durationMs != 152 {
		t.Errorf("duration = %v ms, want 152", got.durationMs)
	}
}

// The case that matters most: Traefik answering on behalf of a dead backend.
// There is no origin status at all, and treating that as "unparseable" would
// hide exactly the outage we exist to catch.
func TestParseJSONLineBackendDown(t *testing.T) {
	line := `{"Duration":1200000,"OriginStatus":0,"DownstreamStatus":502}`

	got, ok := parseLine([]byte(line), FormatJSON)
	if !ok {
		t.Fatal("a 502 with no origin status must still parse")
	}
	if got.statusCode != 502 {
		t.Errorf("status = %d, want 502", got.statusCode)
	}
}

func TestParseCLFLine(t *testing.T) {
	line := `10.0.0.1 - - [11/Aug/2026:12:00:00 +0000] "GET /api/things HTTP/2.0" 503 1234 ` +
		`"-" "Mozilla/5.0" 42 "web@docker" "http://172.18.0.5:3000" 87ms`

	got, ok := parseLine([]byte(line), FormatCLF)
	if !ok {
		t.Fatal("expected the line to parse")
	}
	if got.statusCode != 503 {
		t.Errorf("status = %d, want 503", got.statusCode)
	}
	if got.durationMs != 87 {
		t.Errorf("duration = %v ms, want 87", got.durationMs)
	}
}

func TestParseAutoDetectsFormat(t *testing.T) {
	json := []byte(`{"Duration":5000000,"DownstreamStatus":200}`)
	clf := []byte(`1.2.3.4 - - [x] "GET / HTTP/1.1" 200 1 "-" "-" 1 "r" "s" 5ms`)

	for name, line := range map[string][]byte{"json": json, "clf": clf} {
		got, ok := parseLine(line, FormatAuto)
		if !ok {
			t.Fatalf("%s: expected the line to parse", name)
		}
		if got.statusCode != 200 || got.durationMs != 5 {
			t.Errorf("%s: got %+v, want status 200 and 5ms", name, got)
		}
	}
}

// An access log is written by software we do not control. A line we cannot read
// must be skipped, never fatal, and never counted as a request.
func TestParseRejectsRubbishWithoutPanicking(t *testing.T) {
	rubbish := []string{
		"",
		"   ",
		"not a log line at all",
		`{"Duration":`,
		`{"Duration":100,"DownstreamStatus":0,"OriginStatus":0}`,
		`1.2.3.4 - - [x] "GET / HTTP/1.1" 999 1 "-" "-" 1 "r" "s" 5ms`, // impossible status
		`1.2.3.4 - - [x] "GET / HTTP/1.1" 200 1 "-" "-" 1 "r" "s" notaduration`,
		`1.2.3.4 - - [x] unclosed quote 200`,
	}

	for _, line := range rubbish {
		if _, ok := parseLine([]byte(line), FormatAuto); ok {
			t.Errorf("expected %q to be rejected", line)
		}
	}
}

func TestParseDurationUnits(t *testing.T) {
	cases := map[string]float64{
		"15ms":   15,
		"1.5s":   1500,
		"900µs":  0.9,
		"900us":  0.9,
		"5000ns": 0.005,
		"42":     42,
	}
	for field, want := range cases {
		got, ok := parseDuration(field)
		if !ok {
			t.Fatalf("%q failed to parse", field)
		}
		if diff := got - want; diff > 0.0001 || diff < -0.0001 {
			t.Errorf("%q = %v ms, want %v", field, got, want)
		}
	}
}

// ─── sockstat ───────────────────────────────────────────────────────────────

// Verbatim from a live Coolify host. The key/value pairs start AFTER the "TCP:"
// label — pairing from index 0 instead of 1 leaves every pair off by one, so
// nothing matches and the metric reports as unmeasured forever. That shipped,
// and only real data from a real server showed it.
const realSockstat = `sockets: used 303
TCP: inuse 12 orphan 6 tw 2 alloc 384 mem 18
UDP: inuse 3 mem 760
UDPLITE: inuse 0
RAW: inuse 1
FRAG: inuse 0 memory 0
`

func TestParseSockstat(t *testing.T) {
	inuse, timeWait, found := ParseSockstat(realSockstat)
	if !found {
		t.Fatal("expected the TCP line to be recognised")
	}
	if inuse != 12 {
		t.Errorf("inuse = %d, want 12", inuse)
	}
	if timeWait != 2 {
		t.Errorf("tw = %d, want 2", timeWait)
	}
}

// UDP also has an "inuse" key. Reading it would silently inflate the count.
func TestParseSockstatIgnoresOtherProtocols(t *testing.T) {
	inuse, _, _ := ParseSockstat(realSockstat)
	if inuse == 15 {
		t.Error("UDP's inuse was added to TCP's — only the TCP line counts")
	}
}

func TestParseSockstatIPv6(t *testing.T) {
	inuse, timeWait, found := ParseSockstat("TCP6: inuse 4 orphan 0 tw 1 alloc 9 mem 2\n")
	if !found || inuse != 4 || timeWait != 1 {
		t.Errorf("TCP6 line: inuse=%d tw=%d found=%v; want 4, 1, true", inuse, timeWait, found)
	}
}

func TestParseSockstatMissing(t *testing.T) {
	if _, _, found := ParseSockstat("sockets: used 5\nUDP: inuse 3 mem 1\n"); found {
		t.Error("no TCP line means nothing was measured, not zero")
	}
}

// ─── Histogram ──────────────────────────────────────────────────────────────

func TestHistogramQuantilesAreCloseEnough(t *testing.T) {
	h := newHistogram()
	// 1..1000 ms, one observation each.
	for i := 1; i <= 1000; i++ {
		h.observe(float64(i))
	}

	cases := []struct{ p, want float64 }{
		{0.50, 500},
		{0.95, 950},
		{0.99, 990},
	}
	for _, c := range cases {
		got, ok := h.quantile(c.p)
		if !ok {
			t.Fatalf("p%v returned nothing", c.p*100)
		}
		// Bucketed, so approximate by design. 15% is comfortably inside the
		// bucket widths up here and well within "is the site getting slower".
		tolerance := c.want * 0.15
		if got < c.want-tolerance || got > c.want+tolerance {
			t.Errorf("p%v = %.1f ms, want within %.0f of %.0f", c.p*100, got, tolerance, c.want)
		}
	}
}

func TestHistogramNeverExceedsWhatWasObserved(t *testing.T) {
	h := newHistogram()
	for i := 0; i < 100; i++ {
		h.observe(7)
	}
	for _, p := range []float64{0.5, 0.95, 0.99} {
		got, _ := h.quantile(p)
		if got < 7 || got > 7.0001 {
			t.Errorf("p%v = %v, want 7 — every observation was 7", p*100, got)
		}
	}
}

func TestHistogramEmpty(t *testing.T) {
	h := newHistogram()
	if _, ok := h.quantile(0.5); ok {
		t.Error("an empty histogram must report no quantile, not zero")
	}
}
