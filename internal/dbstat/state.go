package dbstat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Where the agent remembers which engines the owner switched monitoring on
// for. Same home and same reasoning as httplog.StatePath: /var/lib/onserva is
// the executor's StateDirectory — persistent across reboots (a chosen setting
// must not forget itself), writable by the privileged half alone, readable by
// the reporting half.
//
// A variable so the tests can point it somewhere writable.
var StatePath = "/var/lib/onserva/db-metrics.json"

// State stores engine IDs, never sockets or commands. Everything an ID stands
// for is looked up in the compiled-in table at the moment of use, so a file
// edited by hand to name something else resolves to nothing and is ignored.
type State struct {
	Engines   []string  `json:"engines"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Enabled returns the engine IDs monitoring is switched on for, in table
// order, unknown IDs dropped. Every failure — no file, unreadable, malformed
// — is the same answer: none. A broken settings file must degrade one
// feature, never interrupt monitoring.
func Enabled() []string {
	set := enabledSet()
	ids := make([]string, 0, len(set))
	for _, engine := range Engines {
		if set[engine.ID] {
			ids = append(ids, engine.ID)
		}
	}
	return ids
}

func enabledSet() map[string]bool {
	set := make(map[string]bool, len(Engines))
	body, err := os.ReadFile(StatePath)
	if err != nil {
		return set
	}
	var state State
	if err := json.Unmarshal(body, &state); err != nil {
		return set
	}
	for _, id := range state.Engines {
		if _, ok := EngineByID(id); ok {
			set[id] = true
		}
	}
	return set
}

// Enable adds one engine to the monitored set. Called by the executor, which
// runs as root. Enabling twice is not an error — the owner asked for a state,
// and the state already holds.
//
// agentGID hands the file to the unprivileged half's group so it can read it;
// with no such group (gid < 0) it stays root-only, matching spool.Ensure.
func Enable(id string, agentGID int) (Engine, error) {
	engine, ok := EngineByID(id)
	if !ok {
		return Engine{}, &UnknownEngineError{ID: id}
	}

	set := enabledSet()
	set[engine.ID] = true
	ids := make([]string, 0, len(set))
	for _, entry := range Engines {
		if set[entry.ID] {
			ids = append(ids, entry.ID)
		}
	}

	body, err := json.Marshal(State{Engines: ids, UpdatedAt: time.Now().UTC()})
	if err != nil {
		return Engine{}, err
	}

	if err := os.MkdirAll(filepath.Dir(StatePath), 0o755); err != nil {
		return Engine{}, err
	}

	// Written to a temporary name and renamed into place, so the reporting
	// half can never read a half-written file. Ownership first, then an
	// explicit Chmod: the executor's UMask=0077 would otherwise leave the
	// file unreadable by the unprivileged half — the same scar spool.go and
	// httplog/state.go carry.
	temp := StatePath + ".tmp"
	if err := os.WriteFile(temp, body, 0o640); err != nil {
		return Engine{}, err
	}
	if agentGID >= 0 {
		if err := os.Chown(temp, 0, agentGID); err != nil {
			_ = os.Remove(temp)
			return Engine{}, err
		}
	}
	if err := os.Chmod(temp, 0o640); err != nil {
		_ = os.Remove(temp)
		return Engine{}, err
	}
	if err := os.Rename(temp, StatePath); err != nil {
		_ = os.Remove(temp)
		return Engine{}, err
	}

	return engine, nil
}

// Disable removes one engine from the monitored set; the last one out removes
// the file. Called by the executor. An engine that was never enabled is
// success — the owner asked for a state, and the state already holds.
func Disable(id string, agentGID int) (Engine, error) {
	engine, ok := EngineByID(id)
	if !ok {
		return Engine{}, &UnknownEngineError{ID: id}
	}

	set := enabledSet()
	if !set[engine.ID] {
		return engine, nil
	}
	delete(set, engine.ID)

	if len(set) == 0 {
		if err := os.Remove(StatePath); err != nil && !os.IsNotExist(err) {
			return Engine{}, err
		}
		return engine, nil
	}

	ids := make([]string, 0, len(set))
	for _, entry := range Engines {
		if set[entry.ID] {
			ids = append(ids, entry.ID)
		}
	}
	body, err := json.Marshal(State{Engines: ids, UpdatedAt: time.Now().UTC()})
	if err != nil {
		return Engine{}, err
	}
	temp := StatePath + ".tmp"
	if err := os.WriteFile(temp, body, 0o640); err != nil {
		return Engine{}, err
	}
	if agentGID >= 0 {
		if err := os.Chown(temp, 0, agentGID); err != nil {
			_ = os.Remove(temp)
			return Engine{}, err
		}
	}
	if err := os.Chmod(temp, 0o640); err != nil {
		_ = os.Remove(temp)
		return Engine{}, err
	}
	if err := os.Rename(temp, StatePath); err != nil {
		_ = os.Remove(temp)
		return Engine{}, err
	}
	return engine, nil
}

// UnknownEngineError is the expected answer when a newer platform names an
// engine an older agent has never heard of. Declining is correct.
type UnknownEngineError struct{ ID string }

func (e *UnknownEngineError) Error() string {
	return "this agent does not know a database engine called " + e.ID
}
