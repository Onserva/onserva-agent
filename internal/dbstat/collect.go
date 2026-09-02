package dbstat

import (
	"fmt"
	"time"
)

// Metrics is one engine's reading, in exactly the shape the platform's ingest
// endpoint expects. ADDITIVE FOREVER, like every wire type here.
//
// Every field beyond the id is a pointer: "could not see" and "zero" are
// different facts, for a database exactly as for swap. Process figures are
// absent when no process was visible; deep figures are absent whenever the
// socket was not reachable or the counters have no previous visit to rate
// against.
type Metrics struct {
	ID string `json:"id"`

	// From /proc, engine-wide.
	Processes *int     `json:"processes,omitempty"`
	MemMB     *float64 `json:"mem_mb,omitempty"`
	CPUPct    *float64 `json:"cpu_pct,omitempty"`

	// Over the engine's own socket.
	Connections    *int     `json:"connections,omitempty"`
	MaxConnections *int     `json:"max_connections,omitempty"`
	OpsPerS        *float64 `json:"ops_per_s,omitempty"`
	CacheHitPct    *float64 `json:"cache_hit_pct,omitempty"`
	SizeMB         *float64 `json:"size_mb,omitempty"`
	LongestQueryS  *float64 `json:"longest_query_s,omitempty"`
}

// deepCounters is the previous visit's cumulative numbers, per engine, for
// turning totals into rates. ops is "work done" (transactions, questions,
// commands — each engine's own word for it); hit/miss feed the cache ratio.
type deepCounters struct {
	ops  uint64
	hit  uint64
	miss uint64
	at   time.Time
}

// Collector samples the enabled engines each tick.
//
// Rates need two visits, so the first sample after enabling reports the
// gauges and withholds the rates — same as the machine collector priming its
// counters at construction.
type Collector struct {
	enabled []string

	prevTotalJiffies uint64
	prevProcJiffies  map[string]uint64
	prevDeep         map[string]deepCounters

	// One line per engine per state change, not one per tick — the journal
	// rule every other condition here follows.
	unreachable map[string]bool
}

func NewCollector() *Collector {
	return &Collector{
		prevProcJiffies: make(map[string]uint64),
		prevDeep:        make(map[string]deepCounters),
		unreachable:     make(map[string]bool),
	}
}

// SetEnabled replaces the monitored set. Called each tick with whatever the
// state file says, so an authorised switch takes effect without a restart —
// the same contract as SetAccessLog.
func (c *Collector) SetEnabled(ids []string) []string {
	var started []string
	known := make(map[string]bool, len(c.enabled))
	for _, id := range c.enabled {
		known[id] = true
	}
	for _, id := range ids {
		if !known[id] {
			started = append(started, id)
		}
	}
	c.enabled = ids
	return started
}

func (c *Collector) Enabled() []string { return c.enabled }

// Sample reads every enabled engine. Never fails as a whole: an engine that
// cannot be read this tick simply contributes less, and a reason worth
// logging comes back in notes.
func (c *Collector) Sample(now time.Time) (readings []Metrics, notes []string) {
	if len(c.enabled) == 0 {
		return nil, nil
	}

	procs := scanProcesses()
	totalJiffies := readTotalJiffies()

	for _, id := range c.enabled {
		engine, ok := EngineByID(id)
		if !ok {
			continue
		}

		m := Metrics{ID: id}
		proc := procs[id]

		if len(proc.pids) > 0 {
			m.Processes = intPtr(len(proc.pids))
			m.MemMB = floatPtr(roundTo(float64(proc.rssKB)/1024, 1))

			// A share of the whole machine (0–100 across all cores), the same
			// scale as the processor card. Only between two visits, and only
			// while the previous visit is comparable — a counter that went
			// backwards means processes died, and reports nothing.
			prevProc, hasPrev := c.prevProcJiffies[id]
			if hasPrev && c.prevTotalJiffies > 0 && totalJiffies > c.prevTotalJiffies &&
				proc.jiffies >= prevProc {
				pct := float64(proc.jiffies-prevProc) /
					float64(totalJiffies-c.prevTotalJiffies) * 100
				m.CPUPct = floatPtr(roundTo(clampF(pct, 0, 100), 2))
			}
			c.prevProcJiffies[id] = proc.jiffies
		} else {
			delete(c.prevProcJiffies, id)
		}

		if socket := firstSocket(engine); socket != "" {
			if note := c.deepSample(id, socket, now, &m); note != "" {
				notes = append(notes, note)
			}
		}

		readings = append(readings, m)
	}

	c.prevTotalJiffies = totalJiffies
	return readings, notes
}

// deepSample fills the socket-derived half of one reading. Failures degrade to
// absent fields and a once-per-condition note.
func (c *Collector) deepSample(id, socket string, now time.Time, m *Metrics) (note string) {
	var (
		connections, maxConnections int
		counters                    deepCounters
		sizeMB, longestQueryS       float64
		err                         error
	)
	sizeMB, longestQueryS = -1, -1

	switch id {
	case "postgres":
		var deep *pgDeep
		if deep, err = deepPostgres(socket); err == nil {
			connections, maxConnections = deep.connections, deep.maxConnections
			counters = deepCounters{ops: deep.counters.xacts, hit: deep.counters.blksHit,
				miss: deep.counters.blksRead, at: now}
			sizeMB, longestQueryS = deep.sizeMB, deep.longestQueryS
		}
	case "mysql":
		var deep *mysqlDeep
		if deep, err = deepMySQL(socket); err == nil {
			connections, maxConnections = deep.connections, deep.maxConnections
			counters = deepCounters{ops: deep.counters.questions, hit: deep.counters.poolReq - deep.counters.poolRead,
				miss: deep.counters.poolRead, at: now}
			longestQueryS = deep.longestQueryS
			if deep.counters.poolReq < deep.counters.poolRead {
				counters.hit = 0
			}
		}
	case "redis":
		var deep *redisDeep
		if deep, err = deepRedis(socket); err == nil {
			connections, maxConnections = deep.connections, 0
			counters = deepCounters{ops: deep.counters.commands, hit: deep.counters.hits,
				miss: deep.counters.misses, at: now}
			sizeMB = deep.usedMemMB
		}
	default:
		return ""
	}

	if err != nil {
		delete(c.prevDeep, id)
		if !c.unreachable[id] {
			c.unreachable[id] = true
			return fmt.Sprintf("cannot read %s statistics over %s: %v", id, socket, err)
		}
		return ""
	}
	if c.unreachable[id] {
		c.unreachable[id] = false
		note = fmt.Sprintf("%s statistics readable again", id)
	}

	m.Connections = intPtr(connections)
	if maxConnections > 0 {
		m.MaxConnections = intPtr(maxConnections)
	}
	if sizeMB >= 0 {
		m.SizeMB = floatPtr(roundTo(sizeMB, 1))
	}
	if longestQueryS >= 0 {
		m.LongestQueryS = floatPtr(roundTo(longestQueryS, 2))
	}

	// Rates: only between two visits, and only while the counters moved
	// forwards — a restart resets them, and the honest report of a reset is
	// silence for one tick.
	prev, hasPrev := c.prevDeep[id]
	c.prevDeep[id] = counters
	if !hasPrev {
		return note
	}
	elapsed := now.Sub(prev.at).Seconds()
	if elapsed <= 0 || counters.ops < prev.ops || counters.hit < prev.hit ||
		counters.miss < prev.miss {
		return note
	}

	m.OpsPerS = floatPtr(roundTo(float64(counters.ops-prev.ops)/elapsed, 2))

	hits := counters.hit - prev.hit
	misses := counters.miss - prev.miss
	if hits+misses > 0 {
		m.CacheHitPct = floatPtr(roundTo(float64(hits)/float64(hits+misses)*100, 2))
	}
	return note
}

func intPtr(v int) *int             { return &v }
func floatPtr(v float64) *float64   { return &v }
func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func roundTo(v float64, places int) float64 {
	factor := 1.0
	for i := 0; i < places; i++ {
		factor *= 10
	}
	return float64(int64(v*factor+0.5)) / factor
}
