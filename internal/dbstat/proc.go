package dbstat

import (
	"os"
	"strconv"
	"strings"
)

// procSample is what /proc says about one engine's processes right now.
// Jiffies are cumulative; a rate only exists between two samples.
type procSample struct {
	pids    []int
	rssKB   uint64
	jiffies uint64
}

// scanProcesses walks /proc once and buckets every recognised database
// process by engine. Containerised engines are visible here too — the host
// kernel shows every process — which is what makes "your database is using
// 3 GB" honest even when the database itself is behind Docker.
//
// Everything read is world-readable (/proc/<pid>/comm, status, stat). A
// process that vanishes mid-walk is skipped without fuss.
func scanProcesses() map[string]procSample {
	byComm := make(map[string]string, 8)
	for _, engine := range Engines {
		for _, comm := range engine.Comms {
			byComm[comm] = engine.ID
		}
	}

	result := make(map[string]procSample, len(Engines))

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a process directory
		}

		comm, err := os.ReadFile("/proc/" + entry.Name() + "/comm")
		if err != nil {
			continue
		}
		engineID, ok := byComm[strings.TrimSpace(string(comm))]
		if !ok {
			continue
		}

		sample := result[engineID]
		sample.pids = append(sample.pids, pid)
		sample.rssKB += readRSSKB(entry.Name())
		sample.jiffies += readProcJiffies(entry.Name())
		result[engineID] = sample
	}

	return result
}

// readRSSKB reads VmRSS from /proc/<pid>/status, in kilobytes. Zero when the
// process is gone or the line is absent (kernel threads have no VmRSS).
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

// readProcJiffies returns utime+stime from /proc/<pid>/stat.
//
// The comm field (2) is in parentheses and may itself contain spaces or
// parentheses, so fields are counted from AFTER the last ')' — the only
// parsing of this file that survives a process named "my) (evil".
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
	// After ") " the next fields are: state(3) ppid(4) ... utime is field 14,
	// stime field 15 — i.e. indices 11 and 12 of this slice.
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

// readTotalJiffies is the whole machine's cumulative jiffies, for turning a
// process's jiffies delta into a share of the machine — the same 0–100%
// scale as the processor card, so the two can be compared by eye.
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
				break // guest time is already counted in user time
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
