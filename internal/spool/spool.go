// Package spool is the handoff between the agent's two halves.
//
// The split is the whole security design: the process that talks to the
// internet has no privileges, and the process with privileges has no network.
// They meet at two directories under /run, and nothing else.
//
//	/run/onserva/requests/  agent writes, executor reads and removes
//	/run/onserva/results/   executor writes, agent reads and removes
//
// /run is a tmpfs, so both are emptied by a reboot. That is a feature: an
// authorisation that survived a restart and fired hours later would be an
// action nobody remembers approving.
//
// What the executor trusts, and what it does not:
//
//   - It does NOT trust the request to be well-intentioned. Anything running as
//     the agent's user could write one. So the executor re-validates the key
//     against its own compiled-in allowlist and the target against its own
//     pattern, and the worst a forged request can achieve is the same bounded
//     action a real one could.
//   - It does NOT trust a request to still be wanted. Requests carry the time
//     they were written and are ignored once stale, so a file left behind by a
//     crash cannot fire later.
//   - It removes the request BEFORE running the command, so an action that
//     kills the machine mid-restart cannot be replayed on the way back up.
package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Onserva/onserva-agent/internal/fixes"
)

// Root is on tmpfs, cleared on reboot. These are variables rather than
// constants for one reason: the tests point them at a temporary directory.
// Security code that cannot be exercised is a claim, not a guarantee.
var (
	Root        = "/run/onserva"
	RequestsDir = Root + "/requests"
	ResultsDir  = Root + "/results"
)

const (
	// MaxAge is how long an authorised action stays actionable on the box.
	//
	// Short on purpose. The owner pressed Authorise about a problem they were
	// looking at; if the agent could not carry it out within a few minutes,
	// the right thing is to let it lapse and re-propose against fresh readings
	// rather than restart something an hour after anybody thought about it.
	MaxAge = 10 * time.Minute

	// A cap so a runaway platform cannot fill /run.
	maxPending = 32

	// Requests and results are small; anything larger is not ours.
	maxFileBytes = 8 << 10
)

// Request is one authorised action, as handed from the agent to the executor.
type Request struct {
	// ID is the platform's fix_authorizations row. It is echoed back in the
	// result so the audit trail joins up.
	ID string `json:"id"`
	// Action is an allowlist key. Never a command.
	Action fixes.Key `json:"action"`
	// Target names the service or container to act on.
	Target string `json:"target"`
	// WrittenAt is when the agent spooled it, for the staleness check.
	WrittenAt time.Time `json:"written_at"`
}

// Result is what happened, written by the executor for the agent to report.
type Result struct {
	ID         string    `json:"id"`
	OK         bool      `json:"ok"`
	Detail     string    `json:"detail"`
	FinishedAt time.Time `json:"finished_at"`
}

// ErrStale marks a request that sat too long to be worth running.
var ErrStale = errors.New("this authorisation is too old to act on")

// Ensure creates the two directories with the permissions the split depends on.
//
// Called by the executor, which runs as root — the unprivileged half cannot
// create anything under /run itself, and that is deliberate.
func Ensure(agentGID int) error {
	// Root is traversable by anyone; the interesting permissions are one level
	// down. Being able to see that /run/onserva exists tells nobody anything.
	if err := os.MkdirAll(Root, 0o755); err != nil {
		return err
	}
	// The agent writes requests here. Group-writable and group-traversable, but
	// NOT group-readable: the agent has no business listing what else is queued.
	if err := ensureDir(RequestsDir, 0o730, agentGID); err != nil {
		return err
	}
	// The agent reads results here — and removes them once reported, which is
	// why the group needs write on the directory: "take" without unlink is
	// "re-report forever", and the first live fix did exactly that.
	//
	// Group-write does let the agent create files here, and that is a smaller
	// concession than it looks: the agent is already the sole courier of
	// results to the platform, so anything running as its user could tell the
	// platform the same lie directly, with the token it already holds. A
	// forged result cannot cause an action — requests flow the other way, and
	// the platform only accepts result ids it dispatched to this server.
	//
	// NOT setgid, though that would be the idiomatic way to hand each new file
	// to the agent's group: the executor's unit sets RestrictSUIDSGID, which
	// makes any chmod carrying that bit fail with EPERM — and that hardening
	// is worth more than the idiom. Each result file is chowned individually
	// in WriteResult instead.
	return ensureDir(ResultsDir, 0o770, agentGID)
}

func ensureDir(path string, mode os.FileMode, gid int) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	// Ownership before mode: chown is allowed to clear the setgid bit, so the
	// mode must be the last word. MkdirAll also honours the umask, which is
	// the other reason an explicit Chmod is needed at all.
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}

// Write spools an authorised action for the executor. Called by the agent.
func Write(request Request) error {
	if !fixes.Known(request.Action) {
		return fmt.Errorf("%w: %q", fixes.ErrUnknownAction, request.Action)
	}
	if !fixes.ValidTarget(request.Target) {
		return fmt.Errorf("%w: %q", fixes.ErrInvalidTarget, request.Target)
	}
	if !safeID(request.ID) {
		return fmt.Errorf("refusing to spool a request with an unusable id %q", request.ID)
	}

	request.WrittenAt = time.Now().UTC()
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}

	// Written to a temporary name and renamed into place, so the executor can
	// never observe a half-written request — rename within a directory is
	// atomic.
	return writeAtomic(filepath.Join(RequestsDir, request.ID+".json"), body, 0o640)
}

// TakeRequests reads and REMOVES every pending request. Called by the executor.
//
// Removal happens before the caller acts on any of them, so a command that
// takes the machine down with it cannot be replayed on the way back up. A
// request lost to a crash is the safe direction to fail: the platform still has
// the authorisation and can re-issue it, whereas an action repeated without
// anyone asking is not recoverable.
func TakeRequests() ([]Request, error) {
	entries, err := os.ReadDir(RequestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var requests []Request
	var problems []string

	for i, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(RequestsDir, entry.Name())

		body, readErr := readCapped(path)
		_ = os.Remove(path) // taken, whatever happens next

		if i >= maxPending {
			problems = append(problems, "discarded "+entry.Name()+": too many pending requests")
			continue
		}
		if readErr != nil {
			problems = append(problems, "discarded "+entry.Name()+": "+readErr.Error())
			continue
		}

		var request Request
		if err := json.Unmarshal(body, &request); err != nil {
			problems = append(problems, "discarded "+entry.Name()+": not readable as a request")
			continue
		}
		requests = append(requests, request)
	}

	if len(problems) > 0 {
		return requests, errors.New(strings.Join(problems, "; "))
	}
	return requests, nil
}

// Fresh reports whether a request is still worth acting on.
func (r Request) Fresh(now time.Time) bool {
	if r.WrittenAt.IsZero() {
		return false
	}
	age := now.Sub(r.WrittenAt)
	// A negative age means the clock moved, not that the request is from the
	// future. Treat it as suspect rather than as infinitely fresh.
	return age >= 0 && age <= MaxAge
}

// WriteResult records an outcome for the agent to collect. Called by the executor.
//
// The chown is the delivery: the file is written by root, and 0640 root:root
// is a file the agent can only stare at. Handing it to the agent's group is
// done per file because the directory cannot be setgid — the executor's unit
// sets RestrictSUIDSGID, and keeping that hardening is worth the extra call.
// With no agent group on the machine (gid < 0) the result stays root-only,
// which matches everything else Ensure does in that state.
func WriteResult(result Result, agentGID int) error {
	if !safeID(result.ID) {
		return fmt.Errorf("refusing to write a result with an unusable id %q", result.ID)
	}
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	path := filepath.Join(ResultsDir, result.ID+".json")
	if err := writeAtomic(path, body, 0o640); err != nil {
		return err
	}
	if agentGID >= 0 {
		if err := os.Chown(path, 0, agentGID); err != nil {
			return fmt.Errorf("wrote the result but could not hand it to the agent: %w", err)
		}
	}
	return nil
}

// TakeResults reads and removes every pending result. Called by the agent.
//
// Removed on read because the agent reports them onward; a result left behind
// would be reported again on the next check-in, and an audit log that says a
// service was restarted four times when it was restarted once is worse than no
// audit log.
func TakeResults() ([]Result, error) {
	entries, err := os.ReadDir(ResultsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var results []Result
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(ResultsDir, entry.Name())
		body, readErr := readCapped(path)
		_ = os.Remove(path)
		if readErr != nil {
			continue
		}
		var result Result
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}
		results = append(results, result)
	}
	return results, nil
}

// safeID keeps an id from becoming a path.
//
// The id comes from the platform, so it is not to be trusted as a filename: a
// value containing a slash or "…/.." would write outside the spool entirely.
// Ids are database uuids in practice; this accepts that shape and little else.
func safeID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

func writeAtomic(path string, body []byte, mode os.FileMode) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, body, mode); err != nil {
		return err
	}
	if err := os.Chmod(temp, mode); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func readCapped(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	body := make([]byte, maxFileBytes+1)
	n, err := file.Read(body)
	if err != nil && n == 0 {
		return nil, err
	}
	if n > maxFileBytes {
		return nil, errors.New("larger than a request should ever be")
	}
	return body[:n], nil
}
