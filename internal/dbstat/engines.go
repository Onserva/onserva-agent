// Package dbstat watches the database engines that run on a machine —
// without holding a single credential.
//
// Three sources, in increasing depth:
//
//  1. /proc — which engine processes exist, their memory and processor use.
//     World-readable, same privilege story as every other metric.
//  2. The engine's own local socket, authenticated by WHO IS CONNECTING
//     (Postgres peer auth, MySQL/MariaDB unix_socket auth) rather than by any
//     stored secret. The owner grants the agent's user a read-only monitoring
//     role once; the agent never learns a password because there is none.
//  3. Nothing else. No TCP, no config files read, no credentials accepted.
//
// THIS TABLE IS WHY NEITHER A PATH NOR A COMMAND EVER TRAVELS OVER THE WIRE —
// the same guarantee as internal/httplog's candidates. The platform can ask
// for an engine to be monitored or maintained, but what it sends is an ID from
// this list. The socket path, the queries and the maintenance command all live
// here, in the binary the owner can checksum.
//
// An ID must satisfy the fix-target regex on its own — start alphanumeric,
// only [A-Za-z0-9._@-]. TestEngineIDsAreValidTargets holds the line.
package dbstat

import (
	"os"
	"sort"
	"time"
)

// Engine is one database engine this build knows how to recognise.
type Engine struct {
	// ID is short, stable, and safe to use as a fix target. It is the only
	// part of this struct the platform may ever send back to us.
	ID string
	// Label names the engine in words an owner recognises.
	Label string
	// Comms are the process names (/proc/<pid>/comm) that count as this
	// engine. MySQL and MariaDB are one entry on purpose: an owner asked
	// "is my database okay?" does not care which fork answers.
	Comms []string
	// SocketPaths are where the engine's local socket usually lives,
	// compiled in and never accepted from outside. First one present wins.
	SocketPaths []string
}

var Engines = []Engine{
	{
		ID:    "postgres",
		Label: "PostgreSQL",
		Comms: []string{"postgres", "postmaster"},
		SocketPaths: []string{
			"/var/run/postgresql/.s.PGSQL.5432",
		},
	},
	{
		ID:    "mysql",
		Label: "MySQL / MariaDB",
		Comms: []string{"mysqld", "mariadbd"},
		SocketPaths: []string{
			"/var/run/mysqld/mysqld.sock",
		},
	},
	{
		ID:    "redis",
		Label: "Redis",
		Comms: []string{"redis-server", "valkey-server"},
		SocketPaths: []string{
			"/var/run/redis/redis-server.sock",
			"/var/run/redis/redis.sock",
		},
	},
	{
		// Watched from the outside only: this build carries no MongoDB wire
		// client, so SocketPaths is empty and connectable is always false.
		// Process-level visibility is still worth having — "your MongoDB is
		// using 3 GB and climbing" needs no socket.
		ID:          "mongodb",
		Label:       "MongoDB",
		Comms:       []string{"mongod"},
		SocketPaths: nil,
	},
	{
		// The MongoDB arrangement again: Typesense's deeper statistics sit
		// behind its HTTP API and an API key, and this agent holds no
		// credentials by design — so no socket, no probe, and connectable
		// stays honestly false. /proc still answers what matters on a search
		// box: running, and holding how much memory.
		//
		// The comm is the kernel's 15-character truncation of
		// "typesense-server" — read from /proc on a real box, not guessed.
		ID:          "typesense",
		Label:       "Typesense",
		Comms:       []string{"typesense-serve"},
		SocketPaths: nil,
	},
}

// EngineByID returns the compiled-in entry for an ID, and whether it exists.
// This is the lookup that keeps the wire honest: whatever the platform sends
// is matched against this table, and anything not in it is declined.
func EngineByID(id string) (Engine, bool) {
	for _, engine := range Engines {
		if engine.ID == id {
			return engine, true
		}
	}
	return Engine{}, false
}

// Found is an engine that is actually present on this machine, as reported to
// the platform. Present means running, or reachable through a socket — an
// installed-but-stopped engine with no socket is invisible to us, honestly so.
type Found struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Running bool   `json:"running"`

	// SocketPath is which compiled-in socket exists, "" for none. Shown to the
	// owner so they know which door the agent would use; never sent back.
	SocketPath string `json:"socket_path,omitempty"`

	// Connectable is tested by connecting, authenticating and asking the
	// engine one trivial question — the same honesty rule as a log
	// candidate's `readable`. False with a socket present means the owner has
	// not (yet) granted the agent's user a monitoring role, and the dashboard
	// shows the one command that does.
	Connectable bool `json:"connectable"`

	// Monitored is whether readings for this engine are switched on, so the
	// dashboard offers the right button instead of guessing from stored state.
	Monitored bool `json:"monitored"`
}

// probeTimeout bounds every socket probe and every statistics query. A wedged
// engine must cost us a reading, never the agent.
const probeTimeout = 3 * time.Second

// Detect reports which engines are present on this machine.
//
// Absent ones are left out entirely rather than reported as missing, exactly
// like the access-log survey: the platform only needs to know what is there.
//
// It does no more than look and knock: processes are counted, sockets are
// stat'ed, and connectable engines answer one trivial query. Nothing is
// switched on — monitoring an engine is an action the owner authorises.
func Detect() []Found {
	monitored := enabledSet()
	byEngine := scanProcesses()

	found := make([]Found, 0, len(Engines))
	for _, engine := range Engines {
		procs := byEngine[engine.ID]
		socket := firstSocket(engine)
		if len(procs.pids) == 0 && socket == "" {
			continue
		}

		found = append(found, Found{
			ID:          engine.ID,
			Label:       engine.Label,
			Running:     len(procs.pids) > 0,
			SocketPath:  socket,
			Connectable: socket != "" && probe(engine.ID, socket),
			Monitored:   monitored[engine.ID],
		})
	}

	// Stable order regardless of how the table is edited, so a check-in does
	// not look like a change when nothing has changed.
	sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	return found
}

// Present reports whether an engine is visible on this machine at all —
// running processes, or a socket to knock on. The cheap half of Detect (no
// probing), for the executor's pre-flight check.
func Present(id string) bool {
	engine, ok := EngineByID(id)
	if !ok {
		return false
	}
	if firstSocket(engine) != "" {
		return true
	}
	return len(scanProcesses()[id].pids) > 0
}

func firstSocket(engine Engine) string {
	for _, path := range engine.SocketPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSocket != 0 {
			return path
		}
	}
	return ""
}

// probe asks the engine one trivial question, authenticated as this process's
// own user. Any failure — refused, password demanded, timeout — is the same
// answer: not connectable. The error text is not reported anywhere because
// the honest summary for the owner is binary, and the fix is the same
// one-line grant either way.
func probe(engineID, socket string) bool {
	switch engineID {
	case "postgres":
		return probePostgres(socket)
	case "mysql":
		return probeMySQL(socket)
	case "redis":
		return probeRedis(socket)
	default:
		return false
	}
}
