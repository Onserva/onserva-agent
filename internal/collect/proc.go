//go:build linux

// Package collect reads system statistics straight from the Linux kernel's own
// /proc filesystem. No third-party library sits between us and the numbers.
package collect

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/Onserva/onserva-agent/internal/httplog"
)

// ─── Processor ──────────────────────────────────────────────────────────────

// cpuTimes is a snapshot of the cumulative jiffies the kernel has spent in each
// state since boot. Percentages are derived from the difference between two
// snapshots — a single reading tells you nothing.
type cpuTimes struct {
	busy   uint64
	iowait uint64
	total  uint64
}

// readCPUTimes parses the aggregate "cpu" line of /proc/stat:
//
//	cpu  user nice system idle iowait irq softirq steal guest guest_nice
//
// Idle and iowait both count as "not working". Guest time is already included
// in user time by the kernel, so it must not be added again.
func readCPUTimes() (cpuTimes, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, fmt.Errorf("open /proc/stat: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}

		var total, idle, iowait uint64
		for i, raw := range fields[1:] {
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return cpuTimes{}, fmt.Errorf("parse /proc/stat field %d: %w", i, err)
			}
			// Fields 8 and 9 (guest, guest_nice) are already counted in user
			// and nice respectively.
			if i >= 8 {
				continue
			}
			total += value
			if i == 3 || i == 4 { // idle, iowait
				idle += value
			}
			if i == 4 {
				// Tracked separately as well: time spent waiting on storage is
				// not the same problem as time spent working, and a CPU graph
				// alone cannot tell them apart.
				iowait = value
			}
		}
		return cpuTimes{busy: total - idle, iowait: iowait, total: total}, nil
	}

	if err := scanner.Err(); err != nil {
		return cpuTimes{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	return cpuTimes{}, fmt.Errorf("no aggregate cpu line in /proc/stat")
}

// ─── Memory ─────────────────────────────────────────────────────────────────

// readMemInfo returns used and total memory in whole megabytes.
//
// "Used" is deliberately total minus MemAvailable, not total minus MemFree.
// MemAvailable is the kernel's own estimate of what a new program could
// actually claim, so it excludes cache and buffers that would simply be handed
// over on demand. Reporting MemFree would show every healthy Linux box at 95%
// and train the owner to ignore the number.
type memInfo struct {
	usedMB    int
	totalMB   int
	cachedMB  int
	swapUsed  int
	swapTotal int
}

func readMemInfo() (memInfo, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return memInfo{}, fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer file.Close()

	var totalKB, availableKB, freeKB, buffersKB, cachedKB uint64
	var swapTotalKB, swapFreeKB uint64
	var haveAvailable bool

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := parseMemInfoLine(scanner.Text())
		if !ok {
			continue
		}
		switch key {
		case "MemTotal":
			totalKB = value
		case "MemAvailable":
			availableKB, haveAvailable = value, true
		case "MemFree":
			freeKB = value
		case "Buffers":
			buffersKB = value
		case "Cached":
			cachedKB = value
		case "SwapTotal":
			swapTotalKB = value
		case "SwapFree":
			swapFreeKB = value
		}
	}
	if err := scanner.Err(); err != nil {
		return memInfo{}, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	if totalKB == 0 {
		return memInfo{}, fmt.Errorf("MemTotal missing from /proc/meminfo")
	}

	// MemAvailable has existed since Linux 3.14. Fall back for anything older.
	if !haveAvailable {
		availableKB = freeKB + buffersKB + cachedKB
	}
	if availableKB > totalKB {
		availableKB = totalKB
	}
	if swapFreeKB > swapTotalKB {
		swapFreeKB = swapTotalKB
	}

	return memInfo{
		usedMB:    int((totalKB - availableKB) / 1024),
		totalMB:   int(totalKB / 1024),
		cachedMB:  int(cachedKB / 1024),
		swapUsed:  int((swapTotalKB - swapFreeKB) / 1024),
		swapTotal: int(swapTotalKB / 1024),
	}, nil
}

func parseMemInfoLine(line string) (key string, valueKB uint64, ok bool) {
	name, rest, found := strings.Cut(line, ":")
	if !found {
		return "", 0, false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", 0, false
	}
	value, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return name, value, true
}

// ─── Load and uptime ────────────────────────────────────────────────────────

func readLoadAvg() (one, five, fifteen float64, err error) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("read /proc/loadavg: %w", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected /proc/loadavg format")
	}
	values := make([]float64, 3)
	for i := 0; i < 3; i++ {
		values[i], err = strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("parse /proc/loadavg field %d: %w", i, err)
		}
	}
	return values[0], values[1], values[2], nil
}

func readUptimeSeconds() (float64, error) {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, fmt.Errorf("read /proc/uptime: %w", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 1 {
		return 0, fmt.Errorf("unexpected /proc/uptime format")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parse /proc/uptime: %w", err)
	}
	return seconds, nil
}

// ─── Network ────────────────────────────────────────────────────────────────

// netCounters is the cumulative byte count across the interfaces that carry
// real traffic.
type netCounters struct {
	rxBytes   uint64
	txBytes   uint64
	rxErrors  uint64
	txErrors  uint64
	rxDropped uint64
	txDropped uint64
}

// Interfaces we never count. Loopback is internal chatter, and the rest are
// virtual bridges created by Docker/Coolify — counting them would double every
// container's traffic on top of the physical interface that actually carried it.
var ignoredInterfacePrefixes = []string{
	"lo", "docker", "br-", "veth", "virbr", "tun", "tap", "kube", "cni", "flannel",
}

func readNetCounters() (netCounters, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return netCounters{}, fmt.Errorf("open /proc/net/dev: %w", err)
	}
	defer file.Close()

	var counters netCounters
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, rest, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		if isIgnoredInterface(name) {
			continue
		}

		// /proc/net/dev columns, in order:
		//   receive:  bytes packets errs drop fifo frame compressed multicast
		//   transmit: bytes packets errs drop fifo colls carrier compressed
		fields := strings.Fields(rest)
		if len(fields) < 12 {
			continue
		}
		values := make([]uint64, 12)
		bad := false
		for i := 0; i < 12; i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				bad = true // one odd interface must not lose us the whole sample
				break
			}
			values[i] = v
		}
		if bad {
			continue
		}
		counters.rxBytes += values[0]
		counters.rxErrors += values[2]
		counters.rxDropped += values[3]
		counters.txBytes += values[8]
		counters.txErrors += values[10]
		counters.txDropped += values[11]
	}
	if err := scanner.Err(); err != nil {
		return netCounters{}, fmt.Errorf("read /proc/net/dev: %w", err)
	}
	return counters, nil
}

func isIgnoredInterface(name string) bool {
	for _, prefix := range ignoredInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// ─── Disk ───────────────────────────────────────────────────────────────────

// readDiskUsage reports the root filesystem in gigabytes.
//
// The figures are chosen so that used/total matches what `df -h /` prints, to
// the percentage point. Linux reserves a slice of every filesystem for root, so
// "total" here is what is actually usable (used + available) rather than the
// raw size — otherwise Onserva would say 91% while df said 96%, and the owner
// would rightly stop trusting us.
type diskUsage struct {
	usedGB      float64
	totalGB     float64
	inodesUsed  uint64
	inodesTotal uint64
}

func readDiskUsage(path string) (diskUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return diskUsage{}, fmt.Errorf("statfs %s: %w", path, err)
	}

	blockSize := uint64(stat.Bsize)
	usedBytes := (stat.Blocks - stat.Bfree) * blockSize
	usableBytes := usedBytes + (stat.Bavail * blockSize)

	const bytesPerGB = 1024 * 1024 * 1024
	usage := diskUsage{
		usedGB:  float64(usedBytes) / bytesPerGB,
		totalGB: float64(usableBytes) / bytesPerGB,
	}

	// Files is the inode count; it is 0 on filesystems that allocate inodes
	// dynamically (btrfs, and xfs in some configurations). Zero means "not
	// applicable" rather than "full", so it is reported as absent.
	if stat.Files > 0 {
		usage.inodesTotal = stat.Files
		usage.inodesUsed = stat.Files - stat.Ffree
	}
	return usage, nil
}

// ─── Disk throughput ────────────────────────────────────────────────────────

// diskOps is the cumulative count of completed reads and writes across the
// machine's real block devices.
type diskOps struct {
	reads  uint64
	writes uint64
}

// Virtual and duplicate devices. Counting loopback mounts or device-mapper
// layers on top of a physical disk would report the same operation twice.
var ignoredBlockDevicePrefixes = []string{"loop", "ram", "dm-", "sr", "fd", "zram", "md"}

// readDiskOps parses /proc/diskstats. Field 3 is the device name, field 4 the
// count of completed reads and field 8 the count of completed writes.
func readDiskOps() (diskOps, error) {
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return diskOps{}, fmt.Errorf("open /proc/diskstats: %w", err)
	}
	defer file.Close()

	var ops diskOps
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		name := fields[2]
		if isIgnoredBlockDevice(name) || isPartition(name) {
			continue
		}
		reads, err1 := strconv.ParseUint(fields[3], 10, 64)
		writes, err2 := strconv.ParseUint(fields[7], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		ops.reads += reads
		ops.writes += writes
	}
	if err := scanner.Err(); err != nil {
		return diskOps{}, fmt.Errorf("read /proc/diskstats: %w", err)
	}
	return ops, nil
}

func isIgnoredBlockDevice(name string) bool {
	for _, prefix := range ignoredBlockDevicePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// isPartition spots sda1, nvme0n1p2 and friends. Their operations are already
// counted against the whole device, so including them would double everything.
func isPartition(name string) bool {
	if len(name) == 0 {
		return false
	}
	last := name[len(name)-1]
	if last < '0' || last > '9' {
		return false
	}
	// nvme0n1 is a whole device; nvme0n1p1 is a partition.
	if strings.HasPrefix(name, "nvme") || strings.HasPrefix(name, "mmcblk") {
		return strings.Contains(name, "p")
	}
	return true
}

// ─── TCP connections ────────────────────────────────────────────────────────

type tcpCounts struct {
	established int
	timeWait    int
}

// readTCPCounts reads /proc/net/sockstat rather than /proc/net/tcp.
//
// sockstat is a four-line summary; /proc/net/tcp is one line per connection and
// would mean parsing tens of thousands of lines every twenty seconds on a busy
// server. A monitoring agent that measurably loads the machine it is watching
// has defeated its own purpose.
func readTCPCounts() (tcpCounts, error) {
	counts := tcpCounts{established: -1, timeWait: -1}

	for _, path := range []string{"/proc/net/sockstat", "/proc/net/sockstat6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // sockstat6 is absent on machines without IPv6
		}
		inuse, timeWait, found := httplog.ParseSockstat(string(data))
		if !found {
			continue
		}
		if inuse >= 0 {
			counts.established = maxInt(counts.established, 0) + inuse
		}
		if timeWait >= 0 {
			counts.timeWait = maxInt(counts.timeWait, 0) + timeWait
		}
	}
	return counts, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ─── Host identity ──────────────────────────────────────────────────────────

// readOSName returns something a human recognises, e.g. "Ubuntu 24.04.1 LTS".
// An empty string is fine — this is a nicety, never a reason to fail a sample.
func readOSName() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if found && key == "PRETTY_NAME" {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}
