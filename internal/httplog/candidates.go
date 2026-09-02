package httplog

import (
	"os"
	"sort"
)

// Candidates is the agent's compiled-in list of places a reverse proxy keeps
// its access log.
//
// THIS TABLE IS WHY A PATH NEVER TRAVELS OVER THE WIRE. The platform can ask
// for request metrics to be switched on, but what it sends is an ID from this
// list — never a filename. The agent looks the path up here, in the binary it
// was shipped as. That is the same guarantee the fix allowlist makes, for the
// same reason: the target regex in internal/fixes deliberately refuses anything
// that could be a path, and making a button convenient is not a reason to widen
// it.
//
// So an ID must satisfy that regex on its own — start alphanumeric, and contain
// only [A-Za-z0-9._@-]. TestCandidateIDsAreValidTargets holds the line.
//
// Adding an entry is a new agent build, which a client can see and checksum.
var Candidates = []Candidate{
	{
		ID:     "coolify",
		Label:  "Coolify's built-in proxy",
		Path:   "/data/coolify/proxy/access.log",
		Format: FormatJSON,
	},
	{
		ID:     "traefik",
		Label:  "Traefik",
		Path:   "/var/log/traefik/access.log",
		Format: FormatJSON,
	},
	{
		ID:     "nginx",
		Label:  "nginx",
		Path:   "/var/log/nginx/access.log",
		Format: FormatCLF,
	},
	{
		ID:     "caddy",
		Label:  "Caddy",
		Path:   "/var/log/caddy/access.log",
		Format: FormatJSON,
	},
	{
		ID:     "apache",
		Label:  "Apache",
		Path:   "/var/log/apache2/access.log",
		Format: FormatCLF,
	},
}

// Candidate is one known access-log location.
type Candidate struct {
	// ID is short, stable, and safe to use as a fix target. It is the only part
	// of this struct the platform may ever send back to us.
	ID string
	// Label names the proxy in words an owner recognises.
	Label string
	// Path is compiled in and never accepted from outside.
	Path string
	// Format is what that proxy writes by default. FormatAuto would also work,
	// but naming it means a malformed line is a bug rather than a shrug.
	Format Format
}

// Found is a candidate that actually exists on this machine, as reported to the
// platform.
//
// Deliberately three facts and no more. It says where a log is, not what is in
// it — the whole point of this package is that access-log contents are counted
// locally and discarded.
type Found struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Path  string `json:"path"`

	// Readable is the difference between a button that works and a button that
	// lies. The agent runs unprivileged on purpose, so a log it can see in the
	// directory listing may still be one it cannot open — and the dashboard
	// needs to know which, so it can offer the manual instruction instead of a
	// control that would fail.
	Readable bool `json:"readable"`
}

// Detect reports which candidates are present on this machine.
//
// Absent ones are left out entirely rather than reported as missing: the
// platform only needs to know what is there, and a shorter payload says less
// about a machine we do not own.
//
// Readability is tested by opening the file, not by inspecting its mode.
// Permission bits are only part of the answer — ACLs, group membership and
// mount options all decide it too, and the only honest test is the one the
// collector itself will perform.
func Detect() []Found {
	found := make([]Found, 0, len(Candidates))

	for _, candidate := range Candidates {
		info, err := os.Stat(candidate.Path)
		if err != nil || !info.Mode().IsRegular() {
			// Missing, or not a regular file. A directory or a device at that
			// path is not something to offer to switch on.
			continue
		}

		found = append(found, Found{
			ID:       candidate.ID,
			Label:    candidate.Label,
			Path:     candidate.Path,
			Readable: readable(candidate.Path),
		})
	}

	// Stable order regardless of how the table is edited, so a check-in does not
	// look like a change when nothing has changed.
	sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	return found
}

// CandidateByID returns the compiled-in entry for an ID, and whether it exists.
//
// This is the lookup that keeps the wire honest: whatever the platform sends is
// matched against this table, and anything not in it is declined.
func CandidateByID(id string) (Candidate, bool) {
	for _, candidate := range Candidates {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return Candidate{}, false
}

func readable(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}
