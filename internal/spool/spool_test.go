package spool

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Onserva/onserva-agent/internal/fixes"
)

// redirect points the spool at a temporary directory for the duration of a test.
func redirect(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	oldRoot, oldRequests, oldResults := Root, RequestsDir, ResultsDir
	Root = root
	RequestsDir = filepath.Join(root, "requests")
	ResultsDir = filepath.Join(root, "results")
	if err := os.MkdirAll(RequestsDir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ResultsDir, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Root, RequestsDir, ResultsDir = oldRoot, oldRequests, oldResults })
}

func TestRoundTrip(t *testing.T) {
	redirect(t)

	if err := Write(Request{ID: "abc-123", Action: fixes.RestartService, Target: "docker.service"}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := TakeRequests()
	if err != nil {
		t.Fatalf("TakeRequests: %v", err)
	}
	if len(got) != 1 || got[0].ID != "abc-123" || got[0].Target != "docker.service" {
		t.Fatalf("TakeRequests = %+v; want the request just written", got)
	}
	if !got[0].Fresh(time.Now()) {
		t.Error("a request written a moment ago should be fresh")
	}
}

// The property that makes a mid-restart crash safe: a request is gone before it
// is acted on, so it cannot run twice on the way back up.
func TestRequestsAreTakenNotBorrowed(t *testing.T) {
	redirect(t)

	if err := Write(Request{ID: "once", Action: fixes.RestartService, Target: "nginx"}); err != nil {
		t.Fatal(err)
	}
	if _, err := TakeRequests(); err != nil {
		t.Fatal(err)
	}

	again, err := TakeRequests()
	if err != nil {
		t.Fatalf("second TakeRequests: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second TakeRequests = %+v; a taken request must not still be there", again)
	}
}

func TestWriteRefusesWhatTheExecutorWouldRefuse(t *testing.T) {
	redirect(t)

	cases := []struct {
		name    string
		request Request
	}{
		{"unknown action", Request{ID: "a", Action: "reboot_machine", Target: "nginx"}},
		{"target as option", Request{ID: "a", Action: fixes.RestartService, Target: "--force"}},
		{"target as path", Request{ID: "a", Action: fixes.RestartService, Target: "/etc/passwd"}},
	}
	for _, c := range cases {
		if err := Write(c.request); err == nil {
			t.Errorf("%s: Write succeeded; it should be refused before it reaches the spool", c.name)
		}
	}
}

// The id becomes a filename, so it is the one field that could escape the
// directory entirely.
func TestIdCannotBecomeAPath(t *testing.T) {
	redirect(t)

	for _, id := range []string{
		"../escape",
		"a/b",
		"..",
		"",
		"with space",
		"semi;colon",
	} {
		err := Write(Request{ID: id, Action: fixes.RestartService, Target: "nginx"})
		if err == nil {
			t.Errorf("Write with id %q succeeded; an id must never be able to leave the spool", id)
		}
	}

	// And nothing was created outside the requests directory.
	entries, err := os.ReadDir(Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "requests" && entry.Name() != "results" {
			t.Errorf("unexpected %q in the spool root", entry.Name())
		}
	}
}

func TestStaleRequestsAreNotFresh(t *testing.T) {
	now := time.Now()

	old := Request{ID: "old", WrittenAt: now.Add(-MaxAge - time.Second)}
	if old.Fresh(now) {
		t.Error("a request older than MaxAge must not be acted on — nobody remembers authorising it")
	}

	// A clock that moved backwards should read as suspect, not as infinitely fresh.
	future := Request{ID: "future", WrittenAt: now.Add(time.Hour)}
	if future.Fresh(now) {
		t.Error("a request from the future should not be treated as fresh")
	}

	missing := Request{ID: "missing"}
	if missing.Fresh(now) {
		t.Error("a request with no timestamp cannot be shown to be fresh, so it is not")
	}
}

func TestResultsRoundTripAndAreRemoved(t *testing.T) {
	redirect(t)

	if err := WriteResult(Result{ID: "abc-123", OK: true, Detail: "Done.", FinishedAt: time.Now()}, -1); err != nil {
		t.Fatalf("WriteResult: %v", err)
	}

	got, err := TakeResults()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].OK || got[0].ID != "abc-123" {
		t.Fatalf("TakeResults = %+v; want the result just written", got)
	}

	// Read once, reported once. A result left behind would be reported again on
	// the next check-in and the audit log would claim two restarts.
	again, err := TakeResults()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("TakeResults = %+v on the second call; results must be taken, not borrowed", again)
	}
}

func TestUnreadableJunkIsDiscardedNotFatal(t *testing.T) {
	redirect(t)

	if err := os.WriteFile(filepath.Join(RequestsDir, "junk.json"), []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := Write(Request{ID: "good", Action: fixes.RestartService, Target: "nginx"}); err != nil {
		t.Fatal(err)
	}

	got, err := TakeRequests()
	if err == nil {
		t.Error("TakeRequests should report that it discarded something")
	}
	if len(got) != 1 || got[0].ID != "good" {
		t.Fatalf("TakeRequests = %+v; the readable request should still come through", got)
	}
}
