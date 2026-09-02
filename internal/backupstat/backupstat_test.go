package backupstat

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The scanner reads listings and stats, never contents — and reports the
// newest file's age, which is the whole product: "when did backups last
// actually happen?"
func TestScanFindsNewestFile(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	old := filepath.Join(dir, "dump-old.sql")
	fresh := filepath.Join(dir, "nested", "dump-fresh.sql")
	if err := os.MkdirAll(filepath.Dir(fresh), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{old, fresh} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(old, now.Add(-9*24*time.Hour), now.Add(-9*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	files, newest, readable := scan(dir, now)
	if !readable {
		t.Fatal("a readable directory reported unreadable")
	}
	if files != 2 {
		t.Fatalf("files: got %d, want 2", files)
	}
	age := now.Sub(newest)
	if age < time.Hour || age > 3*time.Hour {
		t.Fatalf("newest age: got %s, want ~2h — the fresh file must win", age)
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	files, _, readable := scan(t.TempDir(), time.Now())
	if files != 0 || !readable {
		t.Fatalf("empty dir: files=%d readable=%v; want 0, true", files, readable)
	}
}

// A file stamped in the future (broken clock somewhere) must not produce a
// negative age or win over honest files by lying about time.
func TestScanIgnoresFarFutureTimestamps(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	path := filepath.Join(dir, "from-the-future.tar")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, now.Add(48*time.Hour), now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, newest, _ := scan(dir, now)
	if newest.After(now.Add(time.Hour)) {
		t.Fatalf("a far-future mtime was believed: %s", newest)
	}
}

func TestLocationIDsAreStable(t *testing.T) {
	seen := map[string]bool{}
	for _, location := range Locations {
		if seen[location.ID] {
			t.Errorf("duplicate location id %q", location.ID)
		}
		seen[location.ID] = true
	}
}
