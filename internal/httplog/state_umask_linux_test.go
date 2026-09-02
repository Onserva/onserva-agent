//go:build linux

package httplog

import (
	"os"
	"syscall"
	"testing"
)

// The executor writes this file with UMask=0077, which silently turns 0640 into
// 0600 — the mode a plain os.WriteFile asks for is a REQUEST, filtered by the
// umask of whatever process is running.
//
// The symptom on a real box was the worst kind: the executor reported success,
// the audit log said "Done", the file was on disk with the right contents, and
// the unprivileged half could not read a byte of it. Nothing appeared to be
// wrong anywhere except that the feature did not work.
//
// Linux-only because umask is; these run on the servers, not on Windows.
func TestEnableSurvivesARestrictiveUmask(t *testing.T) {
	useTempState(t)

	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })

	if _, err := Enable("nginx", -1); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	info, err := os.Stat(StatePath)
	if err != nil {
		t.Fatal(err)
	}

	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("state file is %04o, want 0640 — the group cannot read it, so the "+
			"reporting half will never see the setting the executor just wrote", got)
	}
}

func TestEnableLeavesNoTemporaryFileBehindUnderAUmask(t *testing.T) {
	useTempState(t)

	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })

	if _, err := Enable("caddy", -1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(StatePath + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind")
	}
}
