//go:build linux

package collect

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Onserva/onserva-agent/internal/httplog"
)

// The same three-state rule as Phase 7's log_candidates, and the same scar:
// "not watching a proxy", "watching and no request named a site", and "sites
// observed" are three different facts, and omitempty on a bare slice would
// collapse the first two.
func TestHTTPSitesDistinguishesAbsentFromEmpty(t *testing.T) {
	notWatching, err := json.Marshal(Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(notWatching), "http_sites") {
		t.Errorf("no access log must omit the field entirely, got: %s", notWatching)
	}

	empty := []SiteMetrics{}
	watchingQuiet, err := json.Marshal(Metrics{HTTPSites: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(watchingQuiet), `"http_sites":[]`) {
		t.Errorf("a watched log with no sited requests must send an empty array, got: %s", watchingQuiet)
	}
}

func TestSiteMetricsWireFormat(t *testing.T) {
	rate := 33.333
	p95 := 450.5
	red := &httplog.RED{
		Sites: []httplog.SiteRED{
			{
				Host:          "rooplex.co.uk",
				RequestsPerS:  15.0,
				Status5xxPerS: 0.9,
				Status4xxPerS: 0.2,
				ErrorRatePct:  &rate,
				P95Ms:         &p95,
			},
		},
	}

	body, err := json.Marshal(Metrics{HTTPSites: siteMetrics(red)})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"host":"rooplex.co.uk"`,
		`"requests_per_s":15`,
		`"status_5xx_per_s":0.9`,
		`"error_rate_pct":33.33`,
		`"p95_ms":450.5`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("expected %s in %s", want, body)
		}
	}
	// A site with no percentile must omit the key, not send zero.
	if strings.Contains(string(body), `"p50_ms"`) {
		t.Errorf("unmeasured p50 must be omitted, got: %s", body)
	}
}
