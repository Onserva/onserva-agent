// Package backupstat answers one question nobody else in this market asks:
// when did this machine's backups last actually happen?
//
// Small businesses discover a broken backup at restore time, which is the
// most expensive possible moment. The agent cannot know where every backup
// scheme writes, so — the compiled-in-table discipline again — it watches the
// handful of places backups conventionally land, and reports the age of the
// newest file in each. Existence and age only: no filenames leave the machine
// beyond the directory's own compiled-in path, and no file is ever opened.
package backupstat

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Location is one place backups conventionally land.
type Location struct {
	// ID is short, stable, and safe as an identifier on the wire.
	ID string
	// Label names the location in words an owner recognises.
	Label string
	// Path is compiled in and never accepted from outside.
	Path string
	// Watched locations may raise a staleness alert; the others are shown but
	// never alarm. /var/backups is unwatched because the system writes
	// housekeeping files there on its own clock — an owner who has never set
	// up backups must not be congratulated for apt's dpkg archives, nor paged
	// about them.
	Watched bool
}

var Locations = []Location{
	{ID: "coolify-backups", Label: "Coolify's database backups", Path: "/data/coolify/backups", Watched: true},
	{ID: "backup-dir", Label: "the /backup folder", Path: "/backup", Watched: true},
	{ID: "backups-dir", Label: "the /backups folder", Path: "/backups", Watched: true},
	{ID: "var-backups", Label: "system housekeeping backups", Path: "/var/backups", Watched: false},
}

// Found is one location that exists, as reported to the platform.
type Found struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Path  string `json:"path"`
	// Readable is the honesty flag, same as everywhere: a directory the
	// unprivileged agent cannot look inside is reported as such, not guessed at.
	Readable bool `json:"readable"`
	// Files found (bounded — see maxEntries), 0 for an empty directory.
	Files int `json:"files"`
	// Seconds since the newest file was written. Absent when no files.
	NewestAgeSeconds *int64 `json:"newest_age_seconds,omitempty"`
	// Whether a stale age here is worth an alert (see Location.Watched).
	Watched bool `json:"watched"`
}

const (
	maxDepth = 3
	// Enough for any sane backup directory; a bound so a runaway tree costs a
	// truncated count, never a hung survey.
	maxEntries = 5000
)

// Detect reports which backup locations exist and how fresh they are.
// Absent locations are left out entirely, the survey convention.
func Detect(now time.Time) []Found {
	found := make([]Found, 0, len(Locations))

	for _, location := range Locations {
		info, err := os.Stat(location.Path)
		if err != nil || !info.IsDir() {
			continue
		}

		files, newest, readable := scan(location.Path, now)
		entry := Found{
			ID:       location.ID,
			Label:    location.Label,
			Path:     location.Path,
			Readable: readable,
			Files:    files,
			Watched:  location.Watched,
		}
		if files > 0 {
			age := int64(now.Sub(newest).Seconds())
			if age < 0 {
				age = 0
			}
			entry.NewestAgeSeconds = &age
		}
		found = append(found, entry)
	}

	sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
	return found
}

// scan walks a few levels down counting files and keeping the newest mtime.
// It reads directory listings and stats — never file contents.
func scan(root string, now time.Time) (files int, newest time.Time, readable bool) {
	entries := 0
	readable = true

	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				readable = false
			}
			return fs.SkipDir
		}
		if entries >= maxEntries {
			return fs.SkipAll
		}
		entries++

		if entry.IsDir() {
			depth := 0
			for _, c := range path[len(root):] {
				if c == '/' || c == os.PathSeparator {
					depth++
				}
			}
			if depth >= maxDepth {
				return fs.SkipDir
			}
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return nil
		}
		files++
		if mtime := info.ModTime(); mtime.After(newest) && !mtime.After(now.Add(time.Hour)) {
			newest = mtime
		}
		return nil
	})

	return files, newest, readable
}
