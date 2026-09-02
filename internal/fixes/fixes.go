// Package fixes is the agent's own copy of the allowlist.
//
// This is the second half of principle 2, and the half that actually enforces
// it. The platform sends a KEY and a TARGET — never a command. This package
// maps that key to a command the binary was compiled with. Nothing that arrives
// over the network is ever executed as written, so even a fully compromised
// platform can only ask a monitored machine to do something this file already
// knew how to do.
//
// It is deliberately a mirror of web/src/lib/fixes.ts rather than a shared
// artefact fetched at runtime: a list that can be updated remotely is not an
// allowlist, it is a command channel with extra steps. Changing what Onserva
// may do to a server requires shipping a new agent binary, which is a thing a
// client can see, checksum, and refuse.
//
// If the two lists ever disagree, this one wins by construction — the platform
// can propose whatever it likes and the agent will decline anything it does not
// recognise.
package fixes

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Onserva/onserva-agent/internal/dbstat"
	"github.com/Onserva/onserva-agent/internal/httplog"
)

// Key identifies an allowlisted action. The set is closed.
type Key string

const (
	// RestartService stops one program and starts it again. It is the whole of
	// version one, on purpose: every action here has to be pre-tested on a real
	// machine, and a short list ships sooner than a broad one.
	RestartService Key = "restart_service"

	// EnableRequestMetrics starts reading a reverse proxy's access log for
	// request rate, error rate and response times.
	//
	// Its target is a CANDIDATE ID from internal/httplog — "nginx", "coolify" —
	// and never a path. That is the whole point: the target pattern below
	// refuses anything path-shaped, and this action was designed around that
	// rule rather than being an excuse to relax it. The path is looked up in
	// the table this binary was compiled with.
	//
	// It reads; it changes nothing about how the server runs. The reason it
	// still needs authorising is that it points the agent at a file full of
	// visitor request data, which is the owner's decision to make and nobody
	// else's — even though every line is counted and discarded on the machine.
	EnableRequestMetrics Key = "enable_request_metrics"

	// EnableDBMetrics starts reading a database engine's statistics over its
	// own local socket, authenticated by who the agent IS (peer / unix_socket
	// auth) rather than by any stored secret.
	//
	// Its target is an ENGINE ID from internal/dbstat — "postgres", "mysql" —
	// and never a socket path or a query. Same shape, same reason as
	// EnableRequestMetrics: the id is resolved against the table this binary
	// was compiled with, and the target pattern below stays exactly as narrow
	// as it was.
	EnableDBMetrics Key = "enable_db_metrics"

	// DBMaintain runs one engine's routine statistics/vacuum maintenance —
	// commands compiled into this binary, chosen because they are safe to run
	// on a live database: PostgreSQL's `vacuumdb --all --analyze` (reclaims
	// dead row space for reuse and refreshes the query planner's statistics,
	// without exclusive locks), MySQL/MariaDB's `mysqlcheck --analyze` (brief
	// read lock per table). The target is an engine ID, never a database or
	// table name — the maintenance is engine-wide on purpose, so no name a
	// user typed anywhere ever becomes part of a command.
	DBMaintain Key = "db_maintain"

	// DisableRequestMetrics and DisableDBMetrics are the off-switches — every
	// enable deserves one that is a button rather than "delete a file over
	// SSH". They remove settings; nothing about how the server runs changes.
	DisableRequestMetrics Key = "disable_request_metrics"
	DisableDBMetrics      Key = "disable_db_metrics"

	// PurgeSwap empties parked swap back into RAM (swapoff, then swapon).
	// The executor guards it with a compiled-in /proc/meminfo check and
	// REFUSES unless free memory comfortably exceeds what is parked —
	// purging swap on a memory-tight box is how you summon the OOM killer,
	// which is precisely the disaster this product exists to prevent.
	PurgeSwap Key = "purge_swap"

	// FreeDiskSpace clears one of a compiled-in set of reclaimable caches.
	// The target is a CLEANER ID from the table below — "journal",
	// "docker-images", "apt-cache" — the enable_request_metrics pattern
	// applied to disk space: the AI may propose the key and pick an id, and
	// what actually runs was decided when this binary was compiled. Every
	// cleaner removes only machine-rebuildable artefacts: rotated logs past a
	// cap, dangling image layers, cached package downloads. None of them can
	// touch a byte the owner made.
	FreeDiskSpace Key = "free_disk_space"
)

// spaceCleaner is one compiled-in way to reclaim disk space.
type spaceCleaner struct {
	id   string
	what string
	// resolve returns the exact process to run, or an error when the tool is
	// not on this machine — fails closed, reported in the owner's words.
	resolve func() (path string, args []string, err error)
}

var spaceCleaners = []spaceCleaner{
	{
		id:   "journal",
		what: "trimmed the system journal back to 500 MB of the most recent entries",
		resolve: func() (string, []string, error) {
			journalctl, err := exec.LookPath("journalctl")
			if err != nil {
				return "", nil, errors.New("this machine does not keep a systemd journal")
			}
			return journalctl, []string{"--vacuum-size=500M"}, nil
		},
	},
	{
		id:   "docker-images",
		what: "removed dangling Docker image layers (unnamed leftovers from old builds and pulls)",
		resolve: func() (string, []string, error) {
			docker, err := exec.LookPath("docker")
			if err != nil {
				return "", nil, errors.New("Docker is not installed on this machine")
			}
			// prune WITHOUT --all: only dangling layers — the ones nothing
			// references. Never a named image, never a container, never a volume.
			return docker, []string{"image", "prune", "--force"}, nil
		},
	},
	{
		id:   "apt-cache",
		what: "cleared the package manager's cache of downloaded installers",
		resolve: func() (string, []string, error) {
			if aptGet, err := exec.LookPath("apt-get"); err == nil {
				return aptGet, []string{"clean"}, nil
			}
			if dnf, err := exec.LookPath("dnf"); err == nil {
				return dnf, []string{"clean", "packages", "-y"}, nil
			}
			return "", nil, errors.New("no supported package manager was found on this machine")
		},
	},
}

// Known reports whether this build recognises the key at all.
//
// An unknown key is not an error to be worked around — it is the expected
// answer when a newer platform proposes something to an older agent, and
// declining is the correct behaviour.
func Known(key Key) bool {
	switch key {
	case RestartService, EnableRequestMetrics, EnableDBMetrics, DBMaintain,
		DisableRequestMetrics, DisableDBMetrics, FreeDiskSpace, PurgeSwap:
		return true
	}
	return false
}

// target is the same rule web/src/lib/fixes.ts applies, restated here because
// neither side trusts the other.
//
// The leading character class is the load-bearing part: a target starting with
// '-' would be read as an option by whatever it is handed to, which is the one
// injection that survives never using a shell. Everything else is simply what
// systemd unit names and container names are allowed to contain — nothing that
// could be a path, a space, or a shell metacharacter.
var target = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

// ValidTarget reports whether a target is safe to pass to a command.
func ValidTarget(s string) bool {
	return target.MatchString(s)
}

// ErrUnknownAction is returned for a key this build does not implement.
var ErrUnknownAction = errors.New("this agent does not know that action")

// ErrInvalidTarget is returned for a target that fails validation.
var ErrInvalidTarget = errors.New("that is not a name this agent will act on")

// Kind says how the executor carries an action out.
//
// Not every allowlisted action is a program to run. Switching request metrics
// on writes a settings file and starts no process at all, and pretending
// otherwise — by shelling out to `sh -c 'echo … > …'` — would hand a command
// line the very thing this package exists to keep out of one.
type Kind int

const (
	// KindExec runs Path with Args. No shell, ever.
	KindExec Kind = iota
	// KindEnableRequestMetrics is performed by the executor itself: it records
	// the resolved candidate so the reporting half starts reading that log.
	KindEnableRequestMetrics
	// KindEnableDBMetrics likewise: the executor records the engine so the
	// reporting half starts reading its statistics.
	KindEnableDBMetrics
	// KindDisableRequestMetrics and KindDisableDBMetrics remove those
	// settings again — performed by the executor, since it owns the state
	// directory the settings live in.
	KindDisableRequestMetrics
	KindDisableDBMetrics
	// KindPurgeSwap is performed by the executor itself: the meminfo guard
	// must be judged at EXECUTION time (conditions change between authorise
	// and run), and the purge is two commands in sequence, which KindExec's
	// one-process contract deliberately cannot express.
	KindPurgeSwap
)

// Command is what an action resolves to.
//
// For KindExec it is the exact process to run: a program and its arguments,
// never a shell string. Passing arguments as a slice is what makes shell
// metacharacters inert rather than merely discouraged.
type Command struct {
	Kind Kind

	// Exec only.
	Path string
	Args []string

	// KindEnableRequestMetrics only: the candidate ID, already checked against
	// the compiled-in table. The executor resolves it to a path itself; it is
	// carried as an ID rather than a path so that at no point does a filename
	// that came from the network exist in this struct.
	CandidateID string

	// KindEnableDBMetrics only: the engine ID, same discipline as above.
	EngineID string

	// Timeout overrides the executor's default when non-zero. Database
	// maintenance on a large cluster legitimately outlives the 60 seconds a
	// restart is allowed; it is still bounded, because an executor holding
	// root forever is not.
	Timeout time.Duration

	// What: a plain sentence for the audit log, written before the action runs
	// so the record exists even if the machine dies mid-restart.
	What string
}

// Plan turns an authorised action into the command that will run, or refuses.
//
// Resolution for a restart is deterministic and fails closed. A systemd unit is
// preferred because that is what a service on a Linux box normally is; a Docker
// container is the fallback because Coolify-style hosts run their applications
// that way. If the target is neither, nothing runs — the agent does not guess,
// and does not "try both and hope".
func Plan(key Key, name string) (Command, error) {
	if !Known(key) {
		return Command{}, fmt.Errorf("%w: %q", ErrUnknownAction, key)
	}
	if !ValidTarget(name) {
		return Command{}, fmt.Errorf("%w: %q", ErrInvalidTarget, name)
	}

	switch key {
	case RestartService:
		return planRestart(name)
	case EnableRequestMetrics:
		return planEnableRequestMetrics(name)
	case EnableDBMetrics:
		return planEnableDBMetrics(name)
	case DBMaintain:
		return planDBMaintain(name)
	case DisableRequestMetrics:
		// The target names which log is being stopped, for the audit line;
		// there is only ever one setting to remove.
		return Command{
			Kind: KindDisableRequestMetrics,
			What: "switched off request metrics — the agent no longer reads any access log",
		}, nil
	case DisableDBMetrics:
		engine, ok := dbstat.EngineByID(name)
		if !ok {
			return Command{}, fmt.Errorf(
				"%w: this agent does not know a database engine called %q", ErrUnknownAction, name)
		}
		return Command{
			Kind:     KindDisableDBMetrics,
			EngineID: engine.ID,
			What:     fmt.Sprintf("switched off database monitoring for %s", engine.Label),
		}, nil
	case FreeDiskSpace:
		return planFreeDiskSpace(name)
	case PurgeSwap:
		// The target is always "swap" — validated by the regex like every
		// other, carried for the audit line, needed for nothing else.
		return Command{
			Kind: KindPurgeSwap,
			// Reading gigabytes back from disk legitimately takes minutes;
			// bounded, because an executor holding root forever is not.
			Timeout: 10 * time.Minute,
			What:    "purged emergency memory — parked swap moved back into RAM",
		}, nil
	}
	return Command{}, ErrUnknownAction
}

// SwapPurgeVerdict is the compiled-in guard for PurgeSwap, judged against
// /proc/meminfo CONTENT so the rule is testable without a Linux box.
//
// Purging forces every parked page back into RAM at once, so the guard
// demands MemAvailable comfortably exceed what is parked — half again as
// much, because "just enough" plus a busy minute is an OOM kill. Refusing
// is a first-class outcome with a sentence the owner can act on.
func SwapPurgeVerdict(meminfo string) (ok bool, usedKB int64, detail string) {
	values := map[string]int64{}
	for _, line := range strings.Split(meminfo, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		values[name] = value
	}

	available, hasAvailable := values["MemAvailable"]
	total, hasTotal := values["SwapTotal"]
	free, hasFree := values["SwapFree"]
	if !hasAvailable || !hasTotal || !hasFree || free > total {
		// Cannot judge safely → cannot purge safely. Fail closed, say so.
		return false, 0, "this machine's memory figures could not be read, so the purge was not attempted"
	}

	usedKB = total - free
	if total == 0 {
		return false, 0, "this machine has no swap configured — there is nothing to purge"
	}
	if usedKB == 0 {
		// Nothing parked: the purge is a no-op re-arm and always safe.
		return true, 0, ""
	}
	if available < usedKB+usedKB/2 {
		return false, usedKB, fmt.Sprintf(
			"not enough free memory to absorb the %d MB currently parked — purging now could push the machine into a real shortage. Free some memory (or wait for a quieter moment) and try again",
			usedKB/1024)
	}
	return true, usedKB, ""
}

// planFreeDiskSpace maps a cleaner ID to its compiled-in command, failing
// closed on anything not in the table — the line the whole design rests on,
// restated for disk space.
func planFreeDiskSpace(name string) (Command, error) {
	for _, cleaner := range spaceCleaners {
		if cleaner.id != name {
			continue
		}
		path, args, err := cleaner.resolve()
		if err != nil {
			return Command{}, err
		}
		return Command{
			Kind: KindExec,
			Path: path,
			Args: args,
			// A large dangling-layer prune legitimately takes minutes.
			Timeout: 10 * time.Minute,
			What:    cleaner.what,
		}, nil
	}
	return Command{}, fmt.Errorf(
		"%w: this agent does not know a space cleaner called %q", ErrUnknownAction, name)
}

func planRestart(name string) (Command, error) {
	if systemctl, err := exec.LookPath("systemctl"); err == nil && unitExists(systemctl, name) {
		return Command{
			Kind: KindExec,
			Path: systemctl,
			Args: []string{"restart", "--", name},
			What: fmt.Sprintf("restarted the systemd service %q", name),
		}, nil
	}

	if docker, err := exec.LookPath("docker"); err == nil && containerExists(docker, name) {
		return Command{
			Kind: KindExec,
			Path: docker,
			Args: []string{"restart", "--", name},
			What: fmt.Sprintf("restarted the Docker container %q", name),
		}, nil
	}

	return Command{}, fmt.Errorf("no systemd service or Docker container called %q exists on this machine", name)
}

// planEnableRequestMetrics resolves a candidate ID against the compiled-in
// table, and fails closed if it is not there.
//
// This is the line the whole design rests on. `name` arrived over the network;
// what comes out is an ID this binary already knew, and the path it stands for
// is never taken from the caller.
func planEnableRequestMetrics(name string) (Command, error) {
	candidate, ok := httplog.CandidateByID(name)
	if !ok {
		return Command{}, fmt.Errorf(
			"%w: this agent does not know an access log called %q", ErrUnknownAction, name)
	}

	// Existence is checked here so a button pressed against a stale survey fails
	// with something the owner can act on, rather than silently enabling a
	// collector that will never find its file.
	info, err := os.Stat(candidate.Path)
	if err != nil || !info.Mode().IsRegular() {
		return Command{}, fmt.Errorf("%s's access log is not at %s on this machine any more",
			candidate.Label, candidate.Path)
	}
	if file, err := os.Open(candidate.Path); err != nil {
		return Command{}, fmt.Errorf("%s's access log at %s cannot be read by the agent",
			candidate.Label, candidate.Path)
	} else {
		_ = file.Close()
	}

	return Command{
		Kind:        KindEnableRequestMetrics,
		CandidateID: candidate.ID,
		What: fmt.Sprintf("switched on request metrics from %s's access log at %s",
			candidate.Label, candidate.Path),
	}, nil
}

// planEnableDBMetrics resolves an engine ID against the compiled-in table and
// fails closed — the same line planEnableRequestMetrics rests on. Presence is
// checked so a button pressed against a stale survey fails with something the
// owner can act on.
func planEnableDBMetrics(name string) (Command, error) {
	engine, ok := dbstat.EngineByID(name)
	if !ok {
		return Command{}, fmt.Errorf(
			"%w: this agent does not know a database engine called %q", ErrUnknownAction, name)
	}
	if !dbstat.Present(engine.ID) {
		return Command{}, fmt.Errorf("no %s appears to be running on this machine any more",
			engine.Label)
	}
	return Command{
		Kind:     KindEnableDBMetrics,
		EngineID: engine.ID,
		What:     fmt.Sprintf("switched on database monitoring for %s", engine.Label),
	}, nil
}

// planDBMaintain maps an engine ID to its compiled-in maintenance command.
//
// The commands run as the engine's own administrative identity through the
// operating system — `runuser -u postgres` for PostgreSQL, root's unix_socket
// session for MySQL/MariaDB — so, once again, no credential exists anywhere.
// If the client tools are not installed (an engine running in a container,
// say), the plan fails closed with a sentence the owner can act on.
func planDBMaintain(name string) (Command, error) {
	engine, ok := dbstat.EngineByID(name)
	if !ok {
		return Command{}, fmt.Errorf(
			"%w: this agent does not know a database engine called %q", ErrUnknownAction, name)
	}

	switch engine.ID {
	case "postgres":
		runuser, err := exec.LookPath("runuser")
		if err != nil {
			return Command{}, fmt.Errorf("runuser is not installed, so the agent cannot act as the postgres user")
		}
		vacuumdb, err := exec.LookPath("vacuumdb")
		if err != nil {
			return Command{}, fmt.Errorf(
				"vacuumdb is not installed on this machine — PostgreSQL may be running inside a container, where Onserva cannot maintain it")
		}
		return Command{
			Kind: KindExec,
			Path: runuser,
			Args: []string{"-u", "postgres", "--", vacuumdb, "--all", "--analyze"},
			// Engine-wide and bounded; a huge cluster takes minutes, not the
			// restart's sixty seconds.
			Timeout: 15 * time.Minute,
			What:    "ran routine maintenance on PostgreSQL (VACUUM ANALYZE across all databases)",
		}, nil

	case "mysql":
		tool, err := exec.LookPath("mysqlcheck")
		if err != nil {
			if tool, err = exec.LookPath("mariadb-check"); err != nil {
				return Command{}, fmt.Errorf(
					"mysqlcheck is not installed on this machine — MySQL/MariaDB may be running inside a container, where Onserva cannot maintain it")
			}
		}
		return Command{
			Kind:    KindExec,
			Path:    tool,
			Args:    []string{"--all-databases", "--analyze"},
			Timeout: 15 * time.Minute,
			What:    "ran routine maintenance on MySQL/MariaDB (ANALYZE across all databases)",
		}, nil
	}

	return Command{}, fmt.Errorf(
		"this agent has no safe maintenance routine for %s", engine.Label)
}

// unitExists asks systemd whether it knows the unit, rather than attempting the
// restart and reading the failure. Asking first means a typo is reported as a
// typo instead of as a failed action.
func unitExists(systemctl, name string) bool {
	// `show` succeeds for any loadable unit and prints its LoadState. Anything
	// systemd has never heard of comes back "not-found".
	out, err := exec.Command(systemctl, "show", "--property=LoadState", "--value", "--", name).Output()
	if err != nil {
		return false
	}
	return string(trimSpace(out)) == "loaded"
}

func containerExists(docker, name string) bool {
	// Exact-name match. A prefix match would let "web" restart "webhooks".
	out, err := exec.Command(docker, "ps", "--all", "--quiet",
		"--filter", "name=^"+regexp.QuoteMeta(name)+"$").Output()
	if err != nil {
		return false
	}
	return len(trimSpace(out)) > 0
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
