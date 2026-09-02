//go:build linux

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Onserva/onserva-agent/internal/httplog"
)

// Caught on a real server, not in a test: an agent on a machine with no reverse
// proxy surveyed, found nothing, and the platform stored null — which it reads
// as "this agent is too old to know about the feature". The dashboard then told
// the owner to update an agent that was already current, which is precisely the
// wrong-signpost bug this feature was built to remove.
//
// `omitempty` omits an EMPTY slice, so the distinction has to be carried by a
// pointer.
func TestSurveyingAndFindingNothingIsNotTheSameAsNotSurveying(t *testing.T) {
	none := []httplog.Found{}

	surveyed, err := json.Marshal(envelope{LogCandidates: &none})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(surveyed), `"log_candidates":[]`) {
		t.Errorf("a survey that found nothing must send an empty array, got: %s", surveyed)
	}

	quiet, err := json.Marshal(envelope{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(quiet), "log_candidates") {
		t.Errorf("a tick with no survey must omit the field entirely, got: %s", quiet)
	}
}

func TestASurveyWithFindingsIsSentVerbatim(t *testing.T) {
	found := []httplog.Found{
		{ID: "nginx", Label: "nginx", Path: "/var/log/nginx/access.log", Readable: true},
	}

	body, err := json.Marshal(envelope{LogCandidates: &found})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"id":"nginx"`, `"path":"/var/log/nginx/access.log"`, `"readable":true`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("expected %s in %s", want, body)
		}
	}
}

// The platform never sends fix results back, but the agent does — and the same
// omitempty reasoning does NOT apply there: an empty result set genuinely means
// "nothing to report", and there is no third state to distinguish.
func TestNoFixResultsMeansTheFieldIsAbsent(t *testing.T) {
	body, err := json.Marshal(envelope{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "fix_results") {
		t.Errorf("empty fix results should be omitted, got: %s", body)
	}
}
