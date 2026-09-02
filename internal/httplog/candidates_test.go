package httplog

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"testing"
)

// The rule from internal/fixes, restated. If these two ever disagree, the
// platform would offer a button whose target the agent then refuses — which
// looks to an owner like the button is broken.
var fixTarget = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

func TestCandidateIDsAreValidFixTargets(t *testing.T) {
	for _, candidate := range Candidates {
		if !fixTarget.MatchString(candidate.ID) {
			t.Errorf("candidate %q has an ID the fix allowlist would refuse", candidate.ID)
		}
	}
}

func TestCandidateIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, candidate := range Candidates {
		if seen[candidate.ID] {
			t.Errorf("duplicate candidate ID %q — CandidateByID would resolve it arbitrarily", candidate.ID)
		}
		seen[candidate.ID] = true
	}
}

func TestCandidatePathsAreAbsolute(t *testing.T) {
	// `path`, not `filepath`: these are always Linux paths, and the tests are
	// run on Windows too, where filepath.IsAbs wants a drive letter and would
	// call every one of them relative.
	for _, candidate := range Candidates {
		if !path.IsAbs(candidate.Path) {
			t.Errorf("candidate %q has a relative path %q", candidate.ID, candidate.Path)
		}
	}
}

func TestCandidateByIDRefusesAnythingNotInTheTable(t *testing.T) {
	// The whole security argument in one test: what arrives over the wire is
	// matched against the compiled-in table, so a path cannot be smuggled in as
	// an ID.
	for _, id := range []string{
		"/etc/shadow",
		"../../etc/shadow",
		"nginx/../../../etc/passwd",
		"",
		"unknown",
	} {
		if _, ok := CandidateByID(id); ok {
			t.Errorf("CandidateByID(%q) resolved, and must not have", id)
		}
	}

	if _, ok := CandidateByID("nginx"); !ok {
		t.Error("CandidateByID(\"nginx\") did not resolve, but nginx is in the table")
	}
}

func TestDetectReportsOnlyRegularFilesThatExist(t *testing.T) {
	dir := t.TempDir()

	logFile := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logFile, []byte("a line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	aDirectory := filepath.Join(dir, "adir")
	if err := os.Mkdir(aDirectory, 0o755); err != nil {
		t.Fatal(err)
	}

	// Swap the table for the length of this test.
	original := Candidates
	t.Cleanup(func() { Candidates = original })
	Candidates = []Candidate{
		{ID: "present", Label: "Present", Path: logFile, Format: FormatCLF},
		{ID: "missing", Label: "Missing", Path: filepath.Join(dir, "nope.log"), Format: FormatCLF},
		{ID: "adirectory", Label: "A directory", Path: aDirectory, Format: FormatCLF},
	}

	found := Detect()

	if len(found) != 1 {
		t.Fatalf("expected exactly the one real file, got %d: %+v", len(found), found)
	}
	if found[0].ID != "present" {
		t.Errorf("expected the present candidate, got %q", found[0].ID)
	}
	if !found[0].Readable {
		t.Error("a world-readable file we just wrote should be readable")
	}
	if found[0].Path != logFile {
		t.Errorf("path not reported verbatim: %q", found[0].Path)
	}
}

func TestDetectIsSortedByID(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	original := Candidates
	t.Cleanup(func() { Candidates = original })
	Candidates = []Candidate{
		{ID: "zulu", Path: write("z.log"), Format: FormatCLF},
		{ID: "alpha", Path: write("a.log"), Format: FormatCLF},
	}

	found := Detect()
	if len(found) != 2 || found[0].ID != "alpha" || found[1].ID != "zulu" {
		t.Errorf("Detect did not sort by ID: %+v", found)
	}
}
