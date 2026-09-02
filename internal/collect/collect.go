//go:build linux

package collect

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/Onserva/onserva-agent/internal/containers"
	"github.com/Onserva/onserva-agent/internal/dbstat"
	"github.com/Onserva/onserva-agent/internal/httplog"
)

// Sample is one reading, in exactly the shape the platform's ingest endpoint
// expects. Field names and units are part of the contract with the API, so they
// are only ever added to, never renamed.
type Sample struct {
	TS           string  `json:"ts"`
	AgentVersion string  `json:"agent_version"`
	Host         *Host   `json:"host,omitempty"`
	Metrics      Metrics `json:"metrics"`

	// Per-engine database readings, present only for engines the owner has
	// switched monitoring on for. Plain omitempty is correct here (unlike the
	// survey's pointer): absent and empty both mean "nothing is monitored",
	// and the platform treats them alike.
	Databases []dbstat.Metrics `json:"databases,omitempty"`

	// The heaviest containers on a Docker host, by memory — "what is eating
	// this machine", per container, from /proc alone. Absent on machines with
	// no containers, which plain omitempty states correctly.
	Containers []containers.Stat `json:"containers,omitempty"`
}

type Host struct {
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	CPUCores int    `json:"cpu_cores,omitempty"`
}

// Metrics is the wire format. It is ADDITIVE FOREVER: fields are only ever
// added, never renamed or removed, because a static binary on a machine we do
// not control may be years older than the platform receiving it.
//
// Fields that can be genuinely inapplicable — inodes on a filesystem that
// allocates them dynamically, TCP counts on a kernel without sockstat — are
// pointers and omitted entirely rather than sent as zero. "We cannot measure
// this" and "this is zero" are different facts, and a graph that confuses them
// tells the owner something untrue.
type Metrics struct {
	CPUPct        float64 `json:"cpu_pct"`
	MemUsedMB     int     `json:"mem_used_mb"`
	MemTotalMB    int     `json:"mem_total_mb"`
	DiskUsedGB    float64 `json:"disk_used_gb"`
	DiskTotalGB   float64 `json:"disk_total_gb"`
	NetInKbps     float64 `json:"net_in_kbps"`
	NetOutKbps    float64 `json:"net_out_kbps"`
	Load1m        float64 `json:"load_1m"`
	Load5m        float64 `json:"load_5m"`
	Load15m       float64 `json:"load_15m"`
	UptimeSeconds int64   `json:"uptime_seconds"`

	// ── Memory pressure ──────────────────────────────────────────────────
	MemCachedMB int `json:"mem_cached_mb"`
	SwapUsedMB  int `json:"swap_used_mb"`
	SwapTotalMB int `json:"swap_total_mb"`

	// ── Storage ──────────────────────────────────────────────────────────
	IowaitPct     float64 `json:"iowait_pct"`
	DiskReadIOPS  float64 `json:"disk_read_iops"`
	DiskWriteIOPS float64 `json:"disk_write_iops"`
	InodesUsed    *int64  `json:"inodes_used,omitempty"`
	InodesTotal   *int64  `json:"inodes_total,omitempty"`

	// ── Network health ───────────────────────────────────────────────────
	NetInErrorsPerS   float64 `json:"net_in_errors_per_s"`
	NetOutErrorsPerS  float64 `json:"net_out_errors_per_s"`
	NetInDroppedPerS  float64 `json:"net_in_dropped_per_s"`
	NetOutDroppedPerS float64 `json:"net_out_dropped_per_s"`
	TCPEstablished    *int    `json:"tcp_established,omitempty"`
	TCPTimeWait       *int    `json:"tcp_time_wait,omitempty"`

	// ── Application: RED, from the reverse proxy's access log ─────────────
	// All absent when no access log is configured or readable. A server with
	// no web traffic and a server whose log we cannot see must not look alike.
	HTTPRequestsPerS *float64 `json:"http_requests_per_s,omitempty"`
	HTTP5xxPerS      *float64 `json:"http_5xx_per_s,omitempty"`
	HTTP4xxPerS      *float64 `json:"http_4xx_per_s,omitempty"`
	HTTPErrorRatePct *float64 `json:"http_error_rate_pct,omitempty"`
	HTTPP50Ms        *float64 `json:"http_p50_ms,omitempty"`
	HTTPP95Ms        *float64 `json:"http_p95_ms,omitempty"`
	HTTPP99Ms        *float64 `json:"http_p99_ms,omitempty"`

	// The same numbers broken down by site (added 0.6.0, by the owner's
	// explicit 2026-08-13 decision that their own sites' hostnames may leave
	// the box — still no paths, no visitor addresses, no user agents).
	//
	// A *pointer to a slice*, deliberately, and the same scar as Phase 7's
	// log_candidates: nil (key omitted) means "no access log is being watched",
	// while an empty array means "watching, and no request named a site" —
	// which is what a bare-CLF log produces, since CLF carries no Host. An
	// `omitempty` slice would collapse those two truths into one.
	HTTPSites *[]SiteMetrics `json:"http_sites,omitempty"`
}

// SiteMetrics is one site's slice of the window, in wire form. Field names
// mirror the aggregate fields above minus the http_ prefix they sit inside.
type SiteMetrics struct {
	Host          string  `json:"host"`
	RequestsPerS  float64 `json:"requests_per_s"`
	Status5xxPerS float64 `json:"status_5xx_per_s"`
	Status4xxPerS float64 `json:"status_4xx_per_s"`

	ErrorRatePct *float64 `json:"error_rate_pct,omitempty"`
	P50Ms        *float64 `json:"p50_ms,omitempty"`
	P95Ms        *float64 `json:"p95_ms,omitempty"`
	P99Ms        *float64 `json:"p99_ms,omitempty"`
}

// Collector holds the previous counter snapshot. Processor use and network
// throughput are rates, so they only exist as the difference between two
// readings — the first Sample after New() is therefore taken against the
// snapshot captured at construction time.
type Collector struct {
	version string
	root    string

	// Optional: nil on a server with no reverse proxy, which is most of them.
	accessLog *httplog.Collector

	// Optional: nil until main attaches it. Which engines it actually reads
	// is its own state, refreshed each tick from the settings file.
	databases *dbstat.Collector

	// Optional: nil until main attaches it. No setting gates it — container
	// resource use is the same class of fact as process counts, read from the
	// same world-readable /proc.
	containers *containers.Collector
	// Conditions the database sampler wants said out loud, drained by
	// DatabaseNotes — the same once-per-condition contract as AccessLogHealth.
	dbNotes []string

	prevCPU  cpuTimes
	prevNet  netCounters
	prevDisk diskOps
	prevTime time.Time
}

// New primes the counters. Call it one interval before the first Sample.
// accessLog may be nil, in which case no request metrics are reported.
func New(version, rootPath string, accessLog *httplog.Collector) (*Collector, error) {
	cpu, err := readCPUTimes()
	if err != nil {
		return nil, err
	}
	net, err := readNetCounters()
	if err != nil {
		return nil, err
	}
	// Disk statistics are a nicety, not a reason to refuse to start: a container
	// or an unusual kernel may not expose /proc/diskstats at all.
	disk, _ := readDiskOps()

	return &Collector{
		version:   version,
		root:      rootPath,
		accessLog: accessLog,
		prevCPU:   cpu,
		prevNet:   net,
		prevDisk:  disk,
		prevTime:  time.Now(),
	}, nil
}

// SetAccessLog attaches (or detaches) the request-metrics collector while the
// agent is running.
//
// Exists so that switching request metrics on from the dashboard takes effect
// within a tick instead of at the next restart. An owner who presses a button
// and is told to go and restart a service has not really been given a button.
//
// Passing nil detaches it, which is what happens if the log goes away.
func (c *Collector) SetAccessLog(accessLog *httplog.Collector) {
	c.accessLog = accessLog
}

// AccessLogHealth surfaces anything wrong with the access log — missing,
// unreadable, or growing faster than we can drain it — or "" when all is well.
func (c *Collector) AccessLogHealth() string {
	if c.accessLog == nil {
		return ""
	}
	return c.accessLog.Health()
}

// AttachDatabases hands the collector the database sampler. Nil is fine and
// means no database readings, ever — the pre-Phase-9 behaviour.
func (c *Collector) AttachDatabases(databases *dbstat.Collector) {
	c.databases = databases
}

// AttachContainers hands the collector the container sampler. Nil means no
// container readings, ever — the pre-0.7.0 behaviour.
func (c *Collector) AttachContainers(sampler *containers.Collector) {
	c.containers = sampler
}

// DatabaseNotes drains whatever the database sampler wanted logged — engine
// statistics becoming unreadable, or readable again. One line per state
// change, said by the caller that owns the log.
func (c *Collector) DatabaseNotes() []string {
	notes := c.dbNotes
	c.dbNotes = nil
	return notes
}

// Sample takes one reading.
//
// Every metric is required: a partial sample would put a misleading gap or a
// false zero on the owner's graphs, which is worse than a missing point. If any
// source fails we return the error and the caller skips this tick.
func (c *Collector) Sample() (Sample, error) {
	now := time.Now()

	cpu, err := readCPUTimes()
	if err != nil {
		return Sample{}, err
	}
	net, err := readNetCounters()
	if err != nil {
		return Sample{}, err
	}
	mem, err := readMemInfo()
	if err != nil {
		return Sample{}, err
	}
	disk, err := readDiskUsage(c.root)
	if err != nil {
		return Sample{}, err
	}
	load1, load5, load15, err := readLoadAvg()
	if err != nil {
		return Sample{}, err
	}
	uptime, err := readUptimeSeconds()
	if err != nil {
		return Sample{}, err
	}
	// The rest are best-effort: a kernel that does not expose them should cost
	// us those fields, not the whole sample.
	diskOpsNow, diskOpsErr := readDiskOps()
	tcp, _ := readTCPCounts()

	elapsed := now.Sub(c.prevTime).Seconds()
	cpuPct := cpuPercent(c.prevCPU, cpu)
	iowaitPct := iowaitPercent(c.prevCPU, cpu)
	inKbps, outKbps := throughputKbps(c.prevNet, net, elapsed)
	inErrors, outErrors := ratePerSecond(c.prevNet.rxErrors, net.rxErrors, c.prevNet.txErrors, net.txErrors, elapsed)
	inDropped, outDropped := ratePerSecond(c.prevNet.rxDropped, net.rxDropped, c.prevNet.txDropped, net.txDropped, elapsed)

	var readIOPS, writeIOPS float64
	if diskOpsErr == nil {
		readIOPS, writeIOPS = ratePerSecond(c.prevDisk.reads, diskOpsNow.reads, c.prevDisk.writes, diskOpsNow.writes, elapsed)
		c.prevDisk = diskOpsNow
	}

	c.prevCPU = cpu
	c.prevNet = net
	c.prevTime = now

	// Read whatever the proxy has written since the last sample, then close the
	// window. A read failure still leaves whatever we did manage to parse, and
	// the condition is reported separately through AccessLogHealth — it must
	// never cost us the machine metrics.
	var red *httplog.RED
	if c.accessLog != nil {
		_ = c.accessLog.Ingest()
		red = c.accessLog.Sample(now)
	}

	hostname, _ := os.Hostname()

	sample := Sample{
		// UTC with nanoseconds. The platform treats (server, ts) as unique, so
		// a retried sample is stored once no matter how many times it is sent.
		TS:           now.UTC().Format(time.RFC3339Nano),
		AgentVersion: c.version,
		Host: &Host{
			Hostname: hostname,
			OS:       readOSName(),
			CPUCores: runtime.NumCPU(),
		},
		Metrics: Metrics{
			CPUPct:        cpuPct,
			MemUsedMB:     mem.usedMB,
			MemTotalMB:    mem.totalMB,
			DiskUsedGB:    round(disk.usedGB, 2),
			DiskTotalGB:   round(disk.totalGB, 2),
			NetInKbps:     round(inKbps, 2),
			NetOutKbps:    round(outKbps, 2),
			Load1m:        load1,
			Load5m:        load5,
			Load15m:       load15,
			UptimeSeconds: int64(uptime),

			MemCachedMB: mem.cachedMB,
			SwapUsedMB:  mem.swapUsed,
			SwapTotalMB: mem.swapTotal,

			IowaitPct:     iowaitPct,
			DiskReadIOPS:  round(readIOPS, 2),
			DiskWriteIOPS: round(writeIOPS, 2),
			InodesUsed:    optionalInt64(disk.inodesTotal > 0, int64(disk.inodesUsed)),
			InodesTotal:   optionalInt64(disk.inodesTotal > 0, int64(disk.inodesTotal)),

			NetInErrorsPerS:   round(inErrors, 3),
			NetOutErrorsPerS:  round(outErrors, 3),
			NetInDroppedPerS:  round(inDropped, 3),
			NetOutDroppedPerS: round(outDropped, 3),
			TCPEstablished:    optionalInt(tcp.established >= 0, tcp.established),
			TCPTimeWait:       optionalInt(tcp.timeWait >= 0, tcp.timeWait),

			HTTPRequestsPerS: redRate(red, func(r *httplog.RED) float64 { return r.RequestsPerS }),
			HTTP5xxPerS:      redRate(red, func(r *httplog.RED) float64 { return r.Status5xxPerS }),
			HTTP4xxPerS:      redRate(red, func(r *httplog.RED) float64 { return r.Status4xxPerS }),
			HTTPErrorRatePct: redOptional(red, func(r *httplog.RED) *float64 { return r.ErrorRatePct }),
			HTTPP50Ms:        redOptional(red, func(r *httplog.RED) *float64 { return r.P50Ms }),
			HTTPP95Ms:        redOptional(red, func(r *httplog.RED) *float64 { return r.P95Ms }),
			HTTPP99Ms:        redOptional(red, func(r *httplog.RED) *float64 { return r.P99Ms }),
			HTTPSites:        siteMetrics(red),
		},
	}

	// Database readings ride inside the sample so a buffered retry after an
	// outage carries them with the tick they belong to.
	if c.databases != nil {
		readings, notes := c.databases.Sample(now)
		sample.Databases = readings
		c.dbNotes = append(c.dbNotes, notes...)
	}
	if c.containers != nil {
		sample.Containers = c.containers.Sample()
	}

	return sample, nil
}

// siteMetrics converts the per-site windows to wire form. Nil when there is no
// access log at all; a pointer to an empty slice when there is one but no
// request named a site — two different facts, kept different (see the field).
func siteMetrics(red *httplog.RED) *[]SiteMetrics {
	if red == nil {
		return nil
	}
	sites := make([]SiteMetrics, 0, len(red.Sites))
	for _, site := range red.Sites {
		wire := SiteMetrics{
			Host:          site.Host,
			RequestsPerS:  round(site.RequestsPerS, 3),
			Status5xxPerS: round(site.Status5xxPerS, 3),
			Status4xxPerS: round(site.Status4xxPerS, 3),
		}
		if site.ErrorRatePct != nil {
			rounded := round(*site.ErrorRatePct, 2)
			wire.ErrorRatePct = &rounded
		}
		if site.P50Ms != nil {
			rounded := round(*site.P50Ms, 2)
			wire.P50Ms = &rounded
		}
		if site.P95Ms != nil {
			rounded := round(*site.P95Ms, 2)
			wire.P95Ms = &rounded
		}
		if site.P99Ms != nil {
			rounded := round(*site.P99Ms, 2)
			wire.P99Ms = &rounded
		}
		sites = append(sites, wire)
	}
	return &sites
}

// redRate reports a rate only when there is an access log at all. Zero requests
// per second is a real, useful answer; "we are not watching a proxy" is not.
func redRate(red *httplog.RED, pick func(*httplog.RED) float64) *float64 {
	if red == nil {
		return nil
	}
	value := round(pick(red), 3)
	return &value
}

func redOptional(red *httplog.RED, pick func(*httplog.RED) *float64) *float64 {
	if red == nil {
		return nil
	}
	value := pick(red)
	if value == nil {
		return nil
	}
	rounded := round(*value, 2)
	return &rounded
}

func optionalInt(present bool, value int) *int {
	if !present {
		return nil
	}
	return &value
}

func optionalInt64(present bool, value int64) *int64 {
	if !present {
		return nil
	}
	return &value
}

// cpuPercent converts two cumulative snapshots into a percentage.
func cpuPercent(prev, now cpuTimes) float64 {
	totalDelta := now.total - prev.total
	if now.total < prev.total || totalDelta == 0 {
		return 0 // counters wrapped or no time passed
	}
	busyDelta := now.busy - prev.busy
	if now.busy < prev.busy {
		return 0
	}
	return clamp(float64(busyDelta)/float64(totalDelta)*100, 0, 100)
}

// iowaitPercent is the share of processor time spent waiting on storage.
// High iowait alongside low cpu_pct is the signature of slow disk — a problem a
// processor graph on its own cannot show.
func iowaitPercent(prev, now cpuTimes) float64 {
	totalDelta := now.total - prev.total
	if now.total < prev.total || totalDelta == 0 || now.iowait < prev.iowait {
		return 0
	}
	return clamp(float64(now.iowait-prev.iowait)/float64(totalDelta)*100, 0, 100)
}

// ratePerSecond turns two pairs of cumulative counters into per-second rates.
// A counter that has gone backwards means a reset or a wrap, which is reported
// as zero rather than as an enormous spike.
func ratePerSecond(prevA, nowA, prevB, nowB uint64, elapsedSeconds float64) (a, b float64) {
	if elapsedSeconds <= 0 || nowA < prevA || nowB < prevB {
		return 0, 0
	}
	return float64(nowA-prevA) / elapsedSeconds, float64(nowB-prevB) / elapsedSeconds
}

// throughputKbps converts two cumulative byte counters into kilobits per second.
func throughputKbps(prev, now netCounters, elapsedSeconds float64) (in, out float64) {
	if elapsedSeconds <= 0 {
		return 0, 0
	}
	// A counter that has gone backwards means the interface was reset or the
	// 32-bit counter wrapped. Report zero rather than a nonsense spike.
	if now.rxBytes < prev.rxBytes || now.txBytes < prev.txBytes {
		return 0, 0
	}
	const bitsPerByte = 8
	in = float64(now.rxBytes-prev.rxBytes) * bitsPerByte / elapsedSeconds / 1000
	out = float64(now.txBytes-prev.txBytes) * bitsPerByte / elapsedSeconds / 1000
	return in, out
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func round(v float64, places int) float64 {
	factor := 1.0
	for i := 0; i < places; i++ {
		factor *= 10
	}
	return float64(int64(v*factor+0.5)) / factor
}

// Describe is used by `onserva-agent --check` to show a human what it can read.
func (c *Collector) Describe(s Sample) string {
	return fmt.Sprintf(
		"processor %.1f%% · memory %d/%d MB · disk %.1f/%.1f GB · network %.1f/%.1f kb/s · queue %.2f · up %ds",
		s.Metrics.CPUPct, s.Metrics.MemUsedMB, s.Metrics.MemTotalMB,
		s.Metrics.DiskUsedGB, s.Metrics.DiskTotalGB,
		s.Metrics.NetInKbps, s.Metrics.NetOutKbps,
		s.Metrics.Load1m, s.Metrics.UptimeSeconds,
	)
}
