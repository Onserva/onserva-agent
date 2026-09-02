package fixes

import (
	"errors"
	"strings"
	"testing"
)

// This file guards the boundary of everything Onserva may do to a machine it
// does not own. A change that widens it silently is the failure worth catching
// here rather than on a client's server.

func TestKnownIsClosed(t *testing.T) {
	for _, key := range []Key{
		RestartService, EnableRequestMetrics, EnableDBMetrics, DBMaintain,
		DisableRequestMetrics, DisableDBMetrics, FreeDiskSpace,
	} {
		if !Known(key) {
			t.Fatalf("%q should be known — it is on the allowlist", key)
		}
	}
	for _, key := range []Key{
		"", "restart", "reboot", "rm_rf", "restart_service ", "RESTART_SERVICE",
		"enable_request_metrics ", "ENABLE_REQUEST_METRICS",
		"drop_table", "db_repair", "free_disk_space ", "delete_backups",
	} {
		if Known(key) {
			t.Errorf("Known(%q) = true; the allowlist must not accept near-misses", key)
		}
	}
}

// The disk cleaners are a closed table, the candidates discipline: an id not
// compiled in resolves to nothing, however plausible it sounds.
func TestFreeDiskSpaceRefusesUnknownCleaners(t *testing.T) {
	for _, target := range []string{
		"everything", "docker-volumes", "docker", "/var/log", "rm", "journal2",
	} {
		if _, err := Plan(FreeDiskSpace, target); err == nil {
			t.Errorf("Plan(free_disk_space, %q) succeeded; the cleaner table must be closed", target)
		}
	}
}

// The engine ids for the database actions run through the same target gate as
// everything else, and unknown engines are declined.
func TestDBActionsRefuseUnknownEngines(t *testing.T) {
	for _, key := range []Key{EnableDBMetrics, DisableDBMetrics, DBMaintain} {
		for _, target := range []string{"oracle", "sqlite", "postgres; drop", "/var/run"} {
			if _, err := Plan(key, target); err == nil {
				t.Errorf("Plan(%s, %q) succeeded; the engine table must be closed", key, target)
			}
		}
	}
}

// The load-bearing test for Phase 7. A log path must never survive the trip
// from the platform to a command, and the target pattern is what stops it —
// which is why enable_request_metrics takes a candidate ID and not a filename.
func TestEnableRequestMetricsRefusesAnythingPathShaped(t *testing.T) {
	for _, target := range []string{
		"/var/log/nginx/access.log",
		"/etc/shadow",
		"../../etc/shadow",
		"/data/coolify/proxy/access.log",
		"nginx/../../../etc/passwd",
	} {
		if _, err := Plan(EnableRequestMetrics, target); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("Plan(enable_request_metrics, %q) = %v; want ErrInvalidTarget", target, err)
		}
	}
}

func TestEnableRequestMetricsRefusesAnUnknownCandidate(t *testing.T) {
	// Passes the target pattern, but names nothing this binary was compiled
	// with. Declining is the correct answer, not an error to work around.
	_, err := Plan(EnableRequestMetrics, "haproxy")
	if !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("Plan with an unknown candidate = %v; want ErrUnknownAction", err)
	}
}

func TestPlanRefusesUnknownActions(t *testing.T) {
	_, err := Plan("reboot_machine", "nginx")
	if !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("Plan with an unknown action = %v; want ErrUnknownAction", err)
	}
}

func TestPlanRefusesBadTargets(t *testing.T) {
	// Every one of these is refused before anything is looked up on the system,
	// so a malicious target never reaches a process boundary at all.
	for _, target := range []string{
		"--force",                // reads as an option, not a name
		"-h",                     //
		"/etc/passwd",            // a path
		"../../root",             // a traversal
		"nginx; reboot",          // shell metacharacters, inert but unwelcome
		"nginx && reboot",        //
		"nginx|tee",              //
		"nginx $(whoami)",        //
		"nginx\nreboot",          // a newline
		"two words",              //
		"",                       // nothing at all
		strings.Repeat("a", 129), // longer than any real service name
	} {
		if _, err := Plan(RestartService, target); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("Plan(restart_service, %q) = %v; want ErrInvalidTarget", target, err)
		}
	}
}

func TestValidTargetAcceptsRealNames(t *testing.T) {
	for _, name := range []string{
		"docker.service",
		"nginx",
		"typesense",
		"php8.3-fpm.service",
		"user@1000.service",
		"my-app_1",
		strings.Repeat("a", 128),
	} {
		if !ValidTarget(name) {
			t.Errorf("ValidTarget(%q) = false; that is a name a real server uses", name)
		}
	}
}

// The rule that matters most, stated on its own so it cannot be lost in a
// rewrite of the pattern: a target may never begin with a dash.
func TestTargetMayNotLookLikeAnOption(t *testing.T) {
	for _, name := range []string{"-", "-x", "--all", "-rf"} {
		if ValidTarget(name) {
			t.Errorf("ValidTarget(%q) = true; a leading dash is the one injection that survives not using a shell", name)
		}
	}
}
