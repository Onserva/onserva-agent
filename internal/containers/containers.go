// Package containers answers "what, exactly, is eating this machine?" on a
// Docker host — per container, from the outside, with no privileges.
//
// The host kernel shows every containerised process in /proc, and each
// process's cgroup path names the container it belongs to. Summing memory and
// processor time by container id therefore needs nothing but the same
// world-readable files the rest of the agent lives on. What an unprivileged
// agent deliberately CANNOT do is ask the Docker daemon for container names —
// that socket is root-equivalent, and the agent staying unprivileged is a
// security page claim. So a container is reported as its 12-character id plus
// the name of its main process ("postgres", "node"), which is what an owner
// actually recognises anyway.
package containers

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

// Stat is one container's share of the machine, in wire form.
type Stat struct {
	// ID is the container id, shortened to the 12 characters Docker itself
	// shows. Identification only — nothing ever sent back.
	ID string `json:"id"`
	// Comm is the container's busiest process name — the recognisable part.
	Comm string `json:"comm"`
	// MemMB is resident memory summed across the container's processes.
	MemMB float64 `json:"mem_mb"`
	// CPUPct is share of the whole machine (0–100 across all cores), absent
	// on the first sample — a rate needs two visits.
	CPUPct    *float64 `json:"cpu_pct,omitempty"`
	Processes int      `json:"processes"`
}

// The wire carries the heaviest few, not the whole zoo: a Coolify host can
// run dozens of helper containers, and the question is "what is eating the
// box", not "enumerate everything".
const maxReported = 12

// Collector keeps the per-container jiffies of the previous visit.
type Collector struct {
	prevTotalJiffies uint64
	prevJiffies      map[string]uint64
}

func NewCollector() *Collector {
	return &Collector{prevJiffies: make(map[string]uint64)}
}

type accumulator struct {
	rssKB     uint64
	jiffies   uint64
	processes int
	// comm of the process with the largest RSS — "the" process of the container.
	topComm  string
	topRSSKB uint64
}

// Sample walks /proc once and reports the heaviest containers by memory.
func (c *Collector) Sample() []Stat {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	byContainer := make(map[string]*accumulator)
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		id := containerOf(entry.Name())
		if id == "" {
			continue
		}

		acc := byContainer[id]
		if acc == nil {
			acc = &accumulator{}
			byContainer[id] = acc
		}
		acc.processes++
		rss := readRSSKB(entry.Name())
		acc.rssKB += rss
		acc.jiffies += readProcJiffies(entry.Name())
		if rss >= acc.topRSSKB {
			if comm, err := os.ReadFile("/proc/" + entry.Name() + "/comm"); err == nil {
				acc.topComm = strings.TrimSpace(string(comm))
				acc.topRSSKB = rss
			}
		}
	}

	totalJiffies := readTotalJiffies()

	stats := make([]Stat, 0, len(byContainer))
	nextJiffies := make(map[string]uint64, len(byContainer))
	for id, acc := range byContainer {
		nextJiffies[id] = acc.jiffies
		stat := Stat{
			ID:        id,
			Comm:      acc.topComm,
			MemMB:     roundTo(float64(acc.rssKB)/1024, 1),
			Processes: acc.processes,
		}
		prev, hasPrev := c.prevJiffies[id]
		if hasPrev && c.prevTotalJiffies > 0 && totalJiffies > c.prevTotalJiffies &&
			acc.jiffies >= prev {
			pct := float64(acc.jiffies-prev) / float64(totalJiffies-c.prevTotalJiffies) * 100
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
			rounded := roundTo(pct, 2)
			stat.CPUPct = &rounded
		}
		stats = append(stats, stat)
	}
	c.prevJiffies = nextJiffies
	c.prevTotalJiffies = totalJiffies

	// Heaviest first; the cut is by memory because "what is eating the box"
	// is a memory question far more often than a processor one.
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].MemMB != stats[j].MemMB {
			return stats[i].MemMB > stats[j].MemMB
		}
		return stats[i].ID < stats[j].ID
	})
	if len(stats) > maxReported {
		stats = stats[:maxReported]
	}
	return stats
}

// containerOf extracts the container id from /proc/<pid>/cgroup, or "" for a
// process that is not in a container. Handles both shapes in the wild:
//
//	v2:  0::/system.slice/docker-<64hex>.scope
//	v1:  N:cpu:/docker/<64hex>
func containerOf(pid string) string {
	body, err := os.ReadFile("/proc/" + pid + "/cgroup")
	if err != nil {
		return ""
	}
	return ContainerFromCgroup(string(body))
}

// ContainerFromCgroup is the parsing alone, exported for the tests.
func ContainerFromCgroup(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if marker := strings.Index(line, "docker-"); marker >= 0 {
			return shortHex(line[marker+len("docker-"):])
		}
		if marker := strings.Index(line, "/docker/"); marker >= 0 {
			return shortHex(line[marker+len("/docker/"):])
		}
	}
	return ""
}

// shortHex takes the leading hex id and shortens it to Docker's 12 characters.
// Anything that is not a long hex id is not a container id.
func shortHex(s string) string {
	end := 0
	for end < len(s) && isHex(s[end]) {
		end++
	}
	if end < 32 {
		return ""
	}
	return s[:12]
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

func readRSSKB(pid string) uint64 {
	body, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb
	}
	return 0
}

func readProcJiffies(pid string) uint64 {
	body, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return 0
	}
	line := string(body)
	closing := strings.LastIndexByte(line, ')')
	if closing < 0 {
		return 0
	}
	fields := strings.Fields(line[closing+1:])
	if len(fields) < 13 {
		return 0
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0
	}
	return utime + stime
}

func readTotalJiffies() uint64 {
	body, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] != "cpu" {
			continue
		}
		var total uint64
		for i, raw := range fields[1:] {
			if i >= 8 {
				break
			}
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return 0
			}
			total += value
		}
		return total
	}
	return 0
}

func roundTo(v float64, places int) float64 {
	factor := 1.0
	for i := 0; i < places; i++ {
		factor *= 10
	}
	return float64(int64(v*factor+0.5)) / factor
}
