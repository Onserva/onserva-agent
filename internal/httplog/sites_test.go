package httplog

import (
	"fmt"
	"testing"
	"time"
)

// ─── Per-site parsing (2026-08-13, the owner's hostname decision) ───────────

func TestParseJSONLineCarriesTheSite(t *testing.T) {
	line := `{"Duration":152000000,"DownstreamStatus":200,"RequestHost":"Rooplex.co.uk:443"}`

	got, ok := parseLine([]byte(line), FormatJSON)
	if !ok {
		t.Fatal("expected the line to parse")
	}
	if got.host != "rooplex.co.uk" {
		t.Errorf("host = %q, want rooplex.co.uk (lowercased, port stripped)", got.host)
	}
}

func TestCLFLinesCarryNoSite(t *testing.T) {
	// Bare CLF has no Host field. The line still counts in the aggregate; it
	// must not be invented a site.
	line := `10.0.0.1 - - [11/Aug/2026:12:00:00 +0000] "GET /x HTTP/2.0" 200 12 ` +
		`"-" "-" 42 "web@docker" "http://172.18.0.5:3000" 87ms`

	got, ok := parseLine([]byte(line), FormatCLF)
	if !ok {
		t.Fatal("expected the line to parse")
	}
	if got.host != "" {
		t.Errorf("host = %q, want empty for CLF", got.host)
	}
}

// The Host header is client input. Everything a scanner sends must normalise
// to "" (aggregate-only) rather than becoming a bucket name.
func TestNormalizeHostIsAnAllowlist(t *testing.T) {
	cases := map[string]string{
		"Rooplex.co.uk":         "rooplex.co.uk",
		"rooplex.co.uk:443":     "rooplex.co.uk",
		"rooplex.co.uk.":        "rooplex.co.uk",
		"138.68.177.54":         "138.68.177.54",
		"[::1]:443":             "::1",
		"":                      "",
		"  ":                    "",
		"host with spaces":      "",
		"<script>alert(1)</script>": "",
		"a,b":                   "",
		"(other)":               "", // must never collide with the overflow bucket
		"host\nnewline":         "",
	}
	for raw, want := range cases {
		if got := normalizeHost(raw); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", raw, got, want)
		}
	}

	long := make([]byte, 101)
	for i := range long {
		long[i] = 'a'
	}
	if got := normalizeHost(string(long)); got != "" {
		t.Errorf("a 101-char host must be rejected, got %q", got)
	}
}

// ─── Per-site aggregation ───────────────────────────────────────────────────

func siteLine(host string, status int, durationMs int) []byte {
	return []byte(fmt.Sprintf(
		`{"Duration":%d,"DownstreamStatus":%d,"RequestHost":%q}`,
		durationMs*1_000_000, status, host,
	))
}

func collectorWith(t *testing.T, lines ...[]byte) *Collector {
	t.Helper()
	c := New("/nonexistent", FormatAuto, time.Unix(1000, 0))
	for _, line := range lines {
		parsed, ok := parseLine(line, c.format)
		if !ok {
			t.Fatalf("test line failed to parse: %s", line)
		}
		c.requests++
		switch {
		case parsed.statusCode >= 500:
			c.status5xx++
		case parsed.statusCode >= 400:
			c.status4xx++
		}
		c.histogram.observe(parsed.durationMs)
		if window := c.siteFor(parsed.host); window != nil {
			window.requests++
			switch {
			case parsed.statusCode >= 500:
				window.status5xx++
			case parsed.statusCode >= 400:
				window.status4xx++
			}
			window.histogram.observe(parsed.durationMs)
		}
	}
	return c
}

func TestSitesAreReportedBusiestFirst(t *testing.T) {
	c := collectorWith(t,
		siteLine("quiet.example", 200, 10),
		siteLine("busy.example", 200, 100),
		siteLine("busy.example", 500, 200),
		siteLine("busy.example", 404, 300),
	)

	red := c.Sample(time.Unix(1010, 0)) // 10s window
	if red == nil {
		t.Fatal("expected a sample")
	}
	if len(red.Sites) != 2 {
		t.Fatalf("sites = %d, want 2", len(red.Sites))
	}
	busy := red.Sites[0]
	if busy.Host != "busy.example" {
		t.Errorf("first site = %q, want the busiest", busy.Host)
	}
	if busy.RequestsPerS != 0.3 {
		t.Errorf("busy requests/s = %v, want 0.3", busy.RequestsPerS)
	}
	if busy.Status5xxPerS != 0.1 || busy.Status4xxPerS != 0.1 {
		t.Errorf("busy 5xx/4xx = %v/%v, want 0.1/0.1", busy.Status5xxPerS, busy.Status4xxPerS)
	}
	if busy.ErrorRatePct == nil || *busy.ErrorRatePct < 33 || *busy.ErrorRatePct > 34 {
		t.Errorf("busy error rate = %v, want ~33.3", busy.ErrorRatePct)
	}
	if busy.P95Ms == nil {
		t.Error("busy site should carry percentiles")
	}
}

func TestScannerHostsFillOneBucketNotTheMap(t *testing.T) {
	lines := make([][]byte, 0, maxTrackedSites+50)
	for i := 0; i < maxTrackedSites+50; i++ {
		lines = append(lines, siteLine(fmt.Sprintf("scan-%d.example", i), 200, 5))
	}
	c := collectorWith(t, lines...)

	if len(c.sites) > maxTrackedSites+1 {
		t.Fatalf("tracked sites = %d, want at most %d + overflow", len(c.sites), maxTrackedSites)
	}

	red := c.Sample(time.Unix(1010, 0))
	if len(red.Sites) > maxReportedSites+1 {
		t.Fatalf("reported sites = %d, want at most %d + overflow", len(red.Sites), maxReportedSites)
	}

	// Nothing lost: the per-site rows still sum to the aggregate.
	var total float64
	overflows := 0
	for _, site := range red.Sites {
		total += site.RequestsPerS
		if site.Host == overflowSite {
			overflows++
			if site.P95Ms != nil {
				t.Error("the overflow bucket must not carry percentiles")
			}
		}
	}
	if overflows != 1 {
		t.Errorf("overflow buckets = %d, want exactly 1", overflows)
	}
	if diff := total - red.RequestsPerS; diff > 0.001 || diff < -0.001 {
		t.Errorf("per-site sum %v != aggregate %v — the breakdown lost traffic", total, red.RequestsPerS)
	}
}

func TestHostlessLinesStayAggregateOnly(t *testing.T) {
	c := collectorWith(t,
		[]byte(`{"Duration":5000000,"DownstreamStatus":200}`), // no RequestHost
		siteLine("known.example", 200, 5),
	)

	red := c.Sample(time.Unix(1010, 0))
	if red.RequestsPerS != 0.2 {
		t.Errorf("aggregate = %v, want 0.2 — hostless lines still count", red.RequestsPerS)
	}
	if len(red.Sites) != 1 || red.Sites[0].Host != "known.example" {
		t.Fatalf("sites = %+v, want only known.example", red.Sites)
	}
	if red.Sites[0].RequestsPerS != 0.1 {
		t.Errorf("known.example = %v, want 0.1 — it must not absorb hostless lines", red.Sites[0].RequestsPerS)
	}
}

func TestSampleResetsTheSiteWindows(t *testing.T) {
	c := collectorWith(t, siteLine("a.example", 200, 5))

	first := c.Sample(time.Unix(1010, 0))
	if len(first.Sites) != 1 {
		t.Fatalf("first sample sites = %d, want 1", len(first.Sites))
	}

	second := c.Sample(time.Unix(1020, 0))
	if len(second.Sites) != 0 {
		t.Errorf("second sample sites = %d, want 0 — windows must reset", len(second.Sites))
	}
}
