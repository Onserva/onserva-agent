package httplog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Where the agent remembers that request metrics were switched on.
//
// NOT under /run. The spool is on tmpfs precisely so an authorisation cannot
// survive a reboot and fire later, but this is the opposite kind of fact: it is
// a setting the owner chose, and a setting that quietly forgot itself every
// time the machine restarted would be worse than no button at all.
//
// NOT under /etc either, which is where this started and where it failed on a
// real box: the executor runs with ProtectSystem=strict, so everything outside
// its ReadWritePaths is read-only to it. The obvious fix — adding /etc/onserva
// to ReadWritePaths — would hand the privileged half write access to the
// directory holding the agent's token, which is a worse trade than moving the
// file. `StateDirectory=onserva` in onserva-fix.service gives systemd's own
// answer instead: /var/lib/onserva, created and made writable for that unit
// alone, persistent across reboots, and readable by the unprivileged half.
//
// A variable so the tests can point it somewhere writable. Security code that
// cannot be exercised is a claim rather than a guarantee — the same reasoning
// as spool.Root.
var StatePath = "/var/lib/onserva/request-metrics.json"

// State is what the executor writes and the reporting half reads.
//
// It stores the candidate ID, never the path. The path is looked up in the
// compiled-in table at the moment it is used, so a file edited by hand to say
// `"candidate_id": "/etc/shadow"` resolves to nothing and is ignored — the same
// property that makes the wire format safe makes the on-disk format safe.
type State struct {
	CandidateID string    `json:"candidate_id"`
	EnabledAt   time.Time `json:"enabled_at"`
}

// Enabled returns the candidate request metrics are switched on for.
//
// Every failure — no file, unreadable, malformed, or an ID this build does not
// recognise — is the same answer: not enabled. There is no error return on
// purpose. This is called on every tick by the half of the agent whose job is
// to keep reporting, and a broken settings file must degrade one feature, never
// interrupt monitoring.
func Enabled() (Candidate, bool) {
	body, err := os.ReadFile(StatePath)
	if err != nil {
		return Candidate{}, false
	}

	var state State
	if err := json.Unmarshal(body, &state); err != nil {
		return Candidate{}, false
	}

	return CandidateByID(state.CandidateID)
}

// Enable records the choice. Called by the executor, which runs as root.
//
// The ID is validated against the compiled-in table before anything is written,
// so an unknown one is refused here rather than becoming a file that silently
// never works.
//
// agentGID hands the file to the unprivileged half's group so it can read it;
// with no such group (gid < 0) it stays root-only, matching what spool.Ensure
// does in the same situation.
func Enable(id string, agentGID int) (Candidate, error) {
	candidate, ok := CandidateByID(id)
	if !ok {
		return Candidate{}, &UnknownCandidateError{ID: id}
	}

	body, err := json.Marshal(State{CandidateID: candidate.ID, EnabledAt: time.Now().UTC()})
	if err != nil {
		return Candidate{}, err
	}

	if err := os.MkdirAll(filepath.Dir(StatePath), 0o755); err != nil {
		return Candidate{}, err
	}

	// Written to a temporary name and renamed into place, so the reporting half
	// can never read a half-written file — rename within a directory is atomic.
	temp := StatePath + ".tmp"
	if err := os.WriteFile(temp, body, 0o640); err != nil {
		return Candidate{}, err
	}

	// Ownership first, then mode, and the explicit Chmod is not belt-and-braces.
	// onserva-fix.service sets UMask=0077, which turns the 0640 above into 0600
	// and leaves the unprivileged half unable to read its own setting — the file
	// exists, the executor reports success, and nothing happens. spool.go already
	// carries this scar; this is the same one. Chmod goes last because chown is
	// allowed to clear mode bits.
	if agentGID >= 0 {
		if err := os.Chown(temp, 0, agentGID); err != nil {
			_ = os.Remove(temp)
			return Candidate{}, err
		}
	}
	if err := os.Chmod(temp, 0o640); err != nil {
		_ = os.Remove(temp)
		return Candidate{}, err
	}

	if err := os.Rename(temp, StatePath); err != nil {
		_ = os.Remove(temp)
		return Candidate{}, err
	}

	return candidate, nil
}

// Disable removes the setting. Called by the executor, which runs as root.
//
// The reporting half notices the file's absence on its next tick and stops
// reading the log — the same one-tick contract as Enable. A file that was
// never there is success, not an error: the owner asked for a state, and the
// state already holds.
func Disable() error {
	err := os.Remove(StatePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// UnknownCandidateError is returned for an ID that is not in the compiled-in
// table. It is not an internal error — it is the expected answer when a newer
// platform names a log location an older agent has never heard of, and
// declining is correct.
type UnknownCandidateError struct{ ID string }

func (e *UnknownCandidateError) Error() string {
	return "this agent does not know an access log called " + e.ID
}
