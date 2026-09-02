package httplog

import (
	"os"
	"path/filepath"
	"testing"
)

func useTempState(t *testing.T) string {
	t.Helper()
	original := StatePath
	t.Cleanup(func() { StatePath = original })
	StatePath = filepath.Join(t.TempDir(), "request-metrics.json")
	return StatePath
}

func TestNoStateFileMeansNotEnabled(t *testing.T) {
	useTempState(t)
	if _, ok := Enabled(); ok {
		t.Error("Enabled() said yes with no settings file at all")
	}
}

func TestEnableThenRead(t *testing.T) {
	useTempState(t)

	written, err := Enable("nginx", -1)
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if written.ID != "nginx" {
		t.Fatalf("Enable returned %q", written.ID)
	}

	got, ok := Enabled()
	if !ok {
		t.Fatal("Enabled() said no straight after Enable()")
	}
	if got.ID != "nginx" || got.Path != written.Path || got.Format != written.Format {
		t.Errorf("read back %+v, wrote %+v", got, written)
	}
}

func TestEnableRefusesAnIDNotInTheTable(t *testing.T) {
	path := useTempState(t)

	// The important cases are the path-shaped ones: this is the on-disk
	// equivalent of the wire check, and it has to fail the same way.
	for _, id := range []string{"/var/log/anything", "../../etc/shadow", "", "unknown"} {
		if _, err := Enable(id, -1); err == nil {
			t.Errorf("Enable(%q) was accepted, and must not have been", id)
		}
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a refused Enable still wrote a settings file")
	}
}

func TestAHandEditedStateFileCannotNameAPath(t *testing.T) {
	path := useTempState(t)

	// Someone with root could write this by hand. The ID is resolved against
	// the compiled-in table on read, so it resolves to nothing rather than
	// pointing the collector at an arbitrary file.
	if err := os.WriteFile(path, []byte(`{"candidate_id":"/etc/shadow"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := Enabled(); ok {
		t.Errorf("a hand-written path resolved to %+v", got)
	}
}

func TestRubbishInTheStateFileIsJustNotEnabled(t *testing.T) {
	path := useTempState(t)

	// Reporting must never be interrupted by a broken settings file, so every
	// failure has to look the same and none may panic.
	for _, body := range []string{"", "not json at all", "{", `{"candidate_id":123}`, `[]`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := Enabled(); ok {
			t.Errorf("Enabled() said yes for %q", body)
		}
	}
}

func TestEnableIsAtomicallyReplaced(t *testing.T) {
	useTempState(t)

	if _, err := Enable("nginx", -1); err != nil {
		t.Fatal(err)
	}
	if _, err := Enable("caddy", -1); err != nil {
		t.Fatal(err)
	}

	got, ok := Enabled()
	if !ok || got.ID != "caddy" {
		t.Errorf("second Enable did not replace the first: %+v", got)
	}
	if _, err := os.Stat(StatePath + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind")
	}
}
