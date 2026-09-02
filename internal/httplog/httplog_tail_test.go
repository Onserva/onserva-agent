//go:build !windows

// File-tailing behaviour: rotation, truncation and partial writes.
//
// Excluded on Windows, which refuses to rename or delete a file another handle
// holds open — the very thing logrotate does routinely on the Linux servers
// this agent actually runs on. Run them with:
//
//	docker run --rm -v "$PWD:/src" -w /src golang:1.26 go test ./internal/httplog/

package httplog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── Collector ──────────────────────────────────────────────────────────────

func TestCollectorRatesAndErrorSplit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	mustWrite(t, path, "")

	start := time.Now()
	c := New(path, FormatAuto, start)
	// Consume the initial position (a first open starts at end-of-file).
	if err := c.Ingest(); err != nil {
		t.Fatalf("initial ingest: %v", err)
	}

	appendLines(t, path,
		jsonLine(200, 10), jsonLine(200, 20), jsonLine(200, 30),
		jsonLine(404, 5),
		jsonLine(500, 100), jsonLine(502, 200),
	)

	if err := c.Ingest(); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	red := c.Sample(start.Add(10 * time.Second))
	if red == nil {
		t.Fatal("expected a sample")
	}

	if got := red.RequestsPerS; got != 0.6 { // 6 requests / 10s
		t.Errorf("requests/s = %v, want 0.6", got)
	}
	if got := red.Status5xxPerS; got != 0.2 {
		t.Errorf("5xx/s = %v, want 0.2", got)
	}
	if got := red.Status4xxPerS; got != 0.1 {
		t.Errorf("4xx/s = %v, want 0.1", got)
	}
	if red.ErrorRatePct == nil || *red.ErrorRatePct < 33.2 || *red.ErrorRatePct > 33.4 {
		t.Errorf("error rate = %v, want ~33.3 (2 of 6 were 5xx)", red.ErrorRatePct)
	}
}

// A quiet server and a broken one must not look the same.
func TestCollectorReportsNoPercentilesWhenNoRequests(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	mustWrite(t, path, "")

	start := time.Now()
	c := New(path, FormatAuto, start)
	_ = c.Ingest()

	red := c.Sample(start.Add(20 * time.Second))
	if red == nil {
		t.Fatal("expected a sample")
	}
	if red.RequestsPerS != 0 {
		t.Errorf("requests/s = %v, want 0", red.RequestsPerS)
	}
	if red.ErrorRatePct != nil {
		t.Error("error rate must be absent when nothing was requested, not 0%")
	}
	if red.P95Ms != nil {
		t.Error("p95 must be absent when nothing was requested, not 0ms")
	}
}

// Rotation is the normal state of a log file on a real server.
func TestCollectorSurvivesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	mustWrite(t, path, "")

	start := time.Now()
	c := New(path, FormatAuto, start)
	_ = c.Ingest()

	appendLines(t, path, jsonLine(200, 10), jsonLine(200, 10))
	_ = c.Ingest()

	// logrotate: move the old file aside and create a fresh one.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	mustWrite(t, path, "")
	appendLines(t, path, jsonLine(500, 10))

	if err := c.Ingest(); err != nil {
		t.Fatalf("ingest after rotation: %v", err)
	}
	red := c.Sample(start.Add(10 * time.Second))

	// Two from before the rotation, one after — none lost, none double-counted.
	if got := red.RequestsPerS * 10; got < 2.99 || got > 3.01 {
		t.Errorf("counted %v requests across a rotation, want 3", got)
	}
}

func TestCollectorSurvivesTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	mustWrite(t, path, "")

	start := time.Now()
	c := New(path, FormatAuto, start)
	_ = c.Ingest()

	appendLines(t, path, jsonLine(200, 10), jsonLine(200, 10), jsonLine(200, 10))
	_ = c.Ingest()

	// `> access.log` — same inode, now empty.
	mustWrite(t, path, "")
	appendLines(t, path, jsonLine(200, 10))

	if err := c.Ingest(); err != nil {
		t.Fatalf("ingest after truncation: %v", err)
	}
	red := c.Sample(start.Add(10 * time.Second))
	if got := red.RequestsPerS * 10; got < 3.99 || got > 4.01 {
		t.Errorf("counted %v requests across a truncation, want 4", got)
	}
}

// A missing log is the normal state on a server with no reverse proxy. It must
// cost us the request metrics and nothing else.
func TestCollectorToleratesMissingLog(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "nope.log"), FormatAuto, time.Now())

	if err := c.Ingest(); err != nil {
		t.Errorf("a missing log must not be an error, got %v", err)
	}
	if red := c.Sample(time.Now().Add(time.Second)); red == nil {
		t.Error("expected a sample even with no log")
	}
	if health := c.Health(); health == "" {
		t.Error("expected the owner to be told the log is unreadable")
	}
}

// A line still being written must not be parsed until it is finished.
func TestCollectorHoldsBackPartialLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	mustWrite(t, path, "")

	start := time.Now()
	c := New(path, FormatAuto, start)
	_ = c.Ingest()

	// Half a line, no newline yet.
	appendRaw(t, path, `{"Duration":10000000,"Downstr`)
	_ = c.Ingest()
	if red := c.Sample(start.Add(time.Second)); red.RequestsPerS != 0 {
		t.Error("a half-written line must not be counted")
	}

	// The proxy finishes it.
	appendRaw(t, path, "eamStatus\":200}\n")
	_ = c.Ingest()
	if red := c.Sample(start.Add(2 * time.Second)); red.RequestsPerS == 0 {
		t.Error("the completed line should have been counted")
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

func jsonLine(status int, ms int) string {
	return fmt.Sprintf(`{"Duration":%d,"DownstreamStatus":%d,"RequestPath":"/x"}`, ms*1_000_000, status)
}

func mustWrite(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	for _, line := range lines {
		appendRaw(t, path, line+"\n")
	}
}

func appendRaw(t *testing.T, path, text string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	if _, err := file.WriteString(text); err != nil {
		t.Fatalf("append to %s: %v", path, err)
	}
}
