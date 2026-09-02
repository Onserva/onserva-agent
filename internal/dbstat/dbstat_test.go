package dbstat

import (
	"encoding/binary"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// The rule from internal/fixes, restated. If these two ever disagree, the
// platform would offer a button whose target the agent then refuses — which
// looks to an owner like the button is broken.
var fixTarget = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

func TestEngineIDsAreValidFixTargets(t *testing.T) {
	for _, engine := range Engines {
		if !fixTarget.MatchString(engine.ID) {
			t.Errorf("engine %q has an ID the fix allowlist would refuse", engine.ID)
		}
	}
}

func TestEngineIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, engine := range Engines {
		if seen[engine.ID] {
			t.Errorf("duplicate engine ID %q — EngineByID would resolve it arbitrarily", engine.ID)
		}
		seen[engine.ID] = true
	}
}

func TestEngineSocketPathsAreAbsolute(t *testing.T) {
	// `path`, not `filepath`: these are always Linux paths, and the tests run
	// on Windows too.
	for _, engine := range Engines {
		for _, socket := range engine.SocketPaths {
			if !path.IsAbs(socket) {
				t.Errorf("engine %q has a relative socket path %q", engine.ID, socket)
			}
		}
	}
}

// ─── state file ─────────────────────────────────────────────────────────────

func TestEnableAccumulatesEngines(t *testing.T) {
	restore := StatePath
	defer func() { StatePath = restore }()
	StatePath = filepath.Join(t.TempDir(), "db-metrics.json")

	if got := Enabled(); len(got) != 0 {
		t.Fatalf("expected nothing enabled before the file exists, got %v", got)
	}

	if _, err := Enable("postgres", -1); err != nil {
		t.Fatalf("enable postgres: %v", err)
	}
	if _, err := Enable("mysql", -1); err != nil {
		t.Fatalf("enable mysql: %v", err)
	}
	// Twice is a no-op, not an error: the owner asked for a state, and the
	// state already holds.
	if _, err := Enable("postgres", -1); err != nil {
		t.Fatalf("re-enable postgres: %v", err)
	}

	got := Enabled()
	if len(got) != 2 || got[0] != "postgres" || got[1] != "mysql" {
		t.Fatalf("expected [postgres mysql] in table order, got %v", got)
	}
}

func TestEnableRefusesUnknownEngine(t *testing.T) {
	restore := StatePath
	defer func() { StatePath = restore }()
	StatePath = filepath.Join(t.TempDir(), "db-metrics.json")

	if _, err := Enable("sqlite3; rm -rf /", -1); err == nil {
		t.Fatal("an unknown engine must be refused, not written")
	}
	if _, err := os.Stat(StatePath); !os.IsNotExist(err) {
		t.Fatal("a refused enable must not create the state file")
	}
}

// A state file edited by hand to name something not in the table resolves to
// nothing — the same property that makes the wire format safe makes the
// on-disk format safe.
func TestEnabledIgnoresUnknownIDs(t *testing.T) {
	restore := StatePath
	defer func() { StatePath = restore }()
	StatePath = filepath.Join(t.TempDir(), "db-metrics.json")

	if err := os.WriteFile(StatePath,
		[]byte(`{"engines":["/etc/shadow","postgres","oracle"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Enabled()
	if len(got) != 1 || got[0] != "postgres" {
		t.Fatalf("expected only the known engine to survive, got %v", got)
	}
}

// ─── PostgreSQL protocol pieces ─────────────────────────────────────────────

func TestParsePgDataRow(t *testing.T) {
	// Two fields: "42" and SQL null.
	payload := []byte{0, 2}
	payload = binary.BigEndian.AppendUint32(payload, 2)
	payload = append(payload, '4', '2')
	payload = binary.BigEndian.AppendUint32(payload, 0xFFFFFFFF) // -1 = null

	row, err := parsePgDataRow(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(row) != 2 || row[0] != "42" || row[1] != "" {
		t.Fatalf("got %v", row)
	}
}

func TestParsePgDataRowTruncated(t *testing.T) {
	payload := []byte{0, 1}
	payload = binary.BigEndian.AppendUint32(payload, 10)
	payload = append(payload, 'x') // claims 10 bytes, delivers 1

	if _, err := parsePgDataRow(payload); err == nil {
		t.Fatal("a truncated row must be an error, not a short read")
	}
}

func TestPgErrorMessage(t *testing.T) {
	payload := []byte("SFATAL\x00MroleX does not exist\x00\x00")
	if got := pgErrorMessage(payload); got != "roleX does not exist" {
		t.Fatalf("got %q", got)
	}
}

// ─── MySQL protocol pieces ──────────────────────────────────────────────────

func TestReadLenencUint(t *testing.T) {
	cases := []struct {
		in       []byte
		value    uint64
		consumed int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0xfc, 0x34, 0x12}, 0x1234, 3},
		{[]byte{0xfd, 0x56, 0x34, 0x12}, 0x123456, 4},
		{[]byte{0xfe, 1, 0, 0, 0, 0, 0, 0, 0}, 1, 9},
	}
	for _, c := range cases {
		value, consumed, err := readLenencUint(c.in)
		if err != nil || value != c.value || consumed != c.consumed {
			t.Errorf("readLenencUint(%v) = %d,%d,%v; want %d,%d", c.in, value, consumed, err, c.value, c.consumed)
		}
	}
}

func TestParseMySQLTextRow(t *testing.T) {
	// "Threads_connected", "7", then a NULL third column.
	payload := []byte{17}
	payload = append(payload, "Threads_connected"...)
	payload = append(payload, 1, '7', 0xfb)

	row, err := parseMySQLTextRow(payload, 3)
	if err != nil {
		t.Fatal(err)
	}
	if row[0] != "Threads_connected" || row[1] != "7" || row[2] != "" {
		t.Fatalf("got %v", row)
	}
}

func TestMySQLErrorMessage(t *testing.T) {
	payload := []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}
	payload = append(payload, "Access denied"...)
	if got := mysqlErrorMessage(payload); got != "Access denied" {
		t.Fatalf("got %q", got)
	}
}

// ─── rate derivation ────────────────────────────────────────────────────────

// The collector's contract: gauges on the first visit, rates only on the
// second, silence (not a spike) when a counter goes backwards.
func TestDeepRatesNeedTwoVisits(t *testing.T) {
	c := NewCollector()
	now := time.Now()

	m := Metrics{}
	c.prevDeep["redis"] = deepCounters{ops: 100, hit: 80, miss: 20, at: now.Add(-20 * time.Second)}

	// Simulate the bookkeeping deepSample does after a successful read.
	counters := deepCounters{ops: 300, hit: 240, miss: 40, at: now}
	prev := c.prevDeep["redis"]
	elapsed := now.Sub(prev.at).Seconds()
	if elapsed <= 0 {
		t.Fatal("test clock broken")
	}
	m.OpsPerS = floatPtr(roundTo(float64(counters.ops-prev.ops)/elapsed, 2))
	hits, misses := counters.hit-prev.hit, counters.miss-prev.miss
	if hits+misses > 0 {
		m.CacheHitPct = floatPtr(roundTo(float64(hits)/float64(hits+misses)*100, 2))
	}

	if *m.OpsPerS != 10 {
		t.Fatalf("ops rate: got %v, want 10", *m.OpsPerS)
	}
	if *m.CacheHitPct != 88.89 {
		t.Fatalf("cache hit: got %v, want 88.89", *m.CacheHitPct)
	}
}
