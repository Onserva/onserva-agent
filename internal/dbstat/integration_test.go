//go:build integration

package dbstat

import (
	"os"
	"testing"
)

// Real-engine integration tests for the wire clients.
//
// Run inside a Linux container with live engines' sockets mounted at the
// compiled-in locations — see agent/test-integration.sh, which starts
// PostgreSQL, MariaDB and Redis containers, shares their socket directories,
// and runs this with `-tags integration`. Each test skips rather than fails
// when its socket is absent, so a partial rig still proves what it can.

func requireSocket(t *testing.T, engineID string) string {
	t.Helper()
	engine, ok := EngineByID(engineID)
	if !ok {
		t.Fatalf("unknown engine %q", engineID)
	}
	socket := firstSocket(engine)
	if socket == "" {
		t.Skipf("no %s socket present in this rig", engineID)
	}
	return socket
}

func TestIntegrationPostgres(t *testing.T) {
	socket := requireSocket(t, "postgres")

	if !probePostgres(socket) {
		t.Fatal("probePostgres: expected the rigged server to answer")
	}

	deep, err := deepPostgres(socket)
	if err != nil {
		t.Fatalf("deepPostgres: %v", err)
	}
	// Our own session is connected, so at least one.
	if deep.connections < 1 {
		t.Errorf("connections: got %d, want >= 1", deep.connections)
	}
	if deep.maxConnections < 1 {
		t.Errorf("max_connections: got %d, want >= 1", deep.maxConnections)
	}
	if deep.sizeMB <= 0 {
		t.Errorf("sizeMB: got %v, want > 0 (postgres database always exists)", deep.sizeMB)
	}
	if deep.counters.blksHit == 0 {
		t.Error("blksHit: expected some buffer traffic on a fresh server")
	}
	t.Logf("postgres: %d/%d conns, %.1f MB, hit=%d read=%d xacts=%d longest=%.2fs",
		deep.connections, deep.maxConnections, deep.sizeMB,
		deep.counters.blksHit, deep.counters.blksRead, deep.counters.xacts, deep.longestQueryS)
}

func TestIntegrationMySQL(t *testing.T) {
	socket := requireSocket(t, "mysql")

	if !probeMySQL(socket) {
		t.Fatal("probeMySQL: expected the rigged server to answer")
	}

	deep, err := deepMySQL(socket)
	if err != nil {
		t.Fatalf("deepMySQL: %v", err)
	}
	if deep.connections < 1 {
		t.Errorf("connections: got %d, want >= 1", deep.connections)
	}
	if deep.maxConnections < 1 {
		t.Errorf("max_connections: got %d, want >= 1", deep.maxConnections)
	}
	if deep.counters.questions == 0 {
		t.Error("questions: our own queries should have counted")
	}
	t.Logf("mysql: %d/%d conns, questions=%d poolReq=%d poolRead=%d longest=%.2fs",
		deep.connections, deep.maxConnections,
		deep.counters.questions, deep.counters.poolReq, deep.counters.poolRead, deep.longestQueryS)
}

func TestIntegrationRedis(t *testing.T) {
	socket := requireSocket(t, "redis")

	if !probeRedis(socket) {
		t.Fatal("probeRedis: expected the rigged server to answer")
	}

	deep, err := deepRedis(socket)
	if err != nil {
		t.Fatalf("deepRedis: %v", err)
	}
	if deep.connections < 1 {
		t.Errorf("connections: got %d, want >= 1", deep.connections)
	}
	if deep.usedMemMB <= 0 {
		t.Errorf("usedMemMB: got %v, want > 0", deep.usedMemMB)
	}
	if deep.counters.commands == 0 {
		t.Error("commands: our own PING/INFO should have counted")
	}
	t.Logf("redis: %d conns, %.1f MB, commands=%d hits=%d misses=%d",
		deep.connections, deep.usedMemMB,
		deep.counters.commands, deep.counters.hits, deep.counters.misses)
}

func TestIntegrationDetectSeesRiggedEngines(t *testing.T) {
	if os.Getenv("ONSERVA_INTEGRATION_DETECT") == "" {
		t.Skip("set ONSERVA_INTEGRATION_DETECT=1 in the rig to assert on Detect()")
	}
	found := Detect()
	byID := map[string]Found{}
	for _, f := range found {
		byID[f.ID] = f
	}
	for _, id := range []string{"postgres", "mysql", "redis"} {
		f, ok := byID[id]
		if !ok {
			t.Errorf("Detect() did not report %s despite its socket being mounted", id)
			continue
		}
		if !f.Connectable {
			t.Errorf("Detect() reports %s not connectable; the probe should have succeeded", id)
		}
	}
}
