// Package httplog turns a reverse proxy's access log into RED metrics —
// Rate, Errors and Duration — without any of the log leaving the machine.
//
// The agent reads the log locally, counts requests and failures, bins response
// times into a fixed histogram, and reports numbers. Paths, client addresses,
// user agents and referrers are parsed past and discarded. An access log is
// full of personal data; shipping it off a client's server would turn a
// monitoring tool into a data-protection problem, and none of it is needed to
// answer "is the site up and is it fast".
package httplog

import (
	"sort"
	"time"
)

// RED is one window's worth of application health.
//
// The percentile and error-rate fields are pointers because "no requests
// arrived" is not the same as "requests arrived and none failed". A quiet
// server reporting 0% errors and 0ms latency would look identical to a busy
// healthy one, which is exactly the confusion that gets an outage missed.
type RED struct {
	RequestsPerS  float64
	Status4xxPerS float64
	Status5xxPerS float64

	ErrorRatePct *float64
	P50Ms        *float64
	P95Ms        *float64
	P99Ms        *float64

	// The same numbers broken down by site, busiest first, for logs that carry
	// the Host (Traefik JSON does; bare CLF does not — then this is empty and
	// only the aggregate is known). Nil never happens on a Sample; empty means
	// "watching, and nothing named a site".
	Sites []SiteRED
}

// SiteRED is one site's slice of the window. `Host` is the owner's own domain
// as their proxy routed it — the one new thing that leaves the machine, by the
// owner's explicit decision (2026-08-13).
type SiteRED struct {
	Host          string
	RequestsPerS  float64
	Status4xxPerS float64
	Status5xxPerS float64

	ErrorRatePct *float64
	P50Ms        *float64
	P95Ms        *float64
	P99Ms        *float64
}

// The Host header is client input, so the set of sites is bounded twice:
// maxTrackedSites is how many distinct names a window will hold before new
// ones fall into the overflow bucket, and maxReportedSites is how many leave
// the machine. A real box hosts a handful of sites; a scanner can invent
// thousands per minute, and buckets keyed by attacker input must never be
// able to grow the payload.
const (
	maxTrackedSites  = 48
	maxReportedSites = 20
	// Where requests beyond maxTrackedSites are counted. Parenthesised so it
	// can never collide with a real hostname (normalizeHost rejects parens).
	overflowSite = "(other)"
)

// Collector accumulates access-log lines between samples.
type Collector struct {
	tailer *tailer
	format Format

	histogram *histogram
	requests  int64
	status4xx int64
	status5xx int64

	// Per-site windows, keyed by normalised host. Lines whose format carries
	// no host stay aggregate-only rather than being invented a site.
	sites map[string]*siteWindow

	lastSample time.Time

	// Reported once rather than every twenty seconds — a log we cannot read is
	// a persistent condition, and repeating it would bury the journal.
	warnedUnreadable bool
	skippedBytes     int64
	malformedLines   int64
}

// New returns a collector for the given access log. It does not touch the file
// yet: a proxy that has not started, or logging that is switched off, must not
// stop the agent from reporting everything else.
func New(path string, format Format, now time.Time) *Collector {
	return &Collector{
		tailer:     newTailer(path),
		format:     format,
		histogram:  newHistogram(),
		sites:      make(map[string]*siteWindow),
		lastSample: now,
	}
}

// siteWindow is one site's accumulation between samples — the same three
// counters and fixed-size histogram as the aggregate, so per-site memory is
// a few hundred bytes regardless of traffic.
type siteWindow struct {
	requests  int64
	status4xx int64
	status5xx int64
	histogram *histogram
}

func (c *Collector) siteFor(host string) *siteWindow {
	if host == "" {
		return nil
	}
	if window, ok := c.sites[host]; ok {
		return window
	}
	if len(c.sites) >= maxTrackedSites {
		// The cap is the security property: the Host header is client input,
		// and a scanner inventing names must fill one shared bucket, not the map.
		if window, ok := c.sites[overflowSite]; ok {
			return window
		}
		host = overflowSite
	}
	window := &siteWindow{histogram: newHistogram()}
	c.sites[host] = window
	return window
}

// Ingest reads whatever the proxy has written since last time.
// Errors are returned for the caller to log; they never stop collection.
func (c *Collector) Ingest() error {
	lines, skipped, err := c.tailer.readLines()
	c.skippedBytes += skipped

	for _, line := range lines {
		parsed, ok := parseLine(line, c.format)
		if !ok {
			c.malformedLines++
			continue
		}
		c.requests++
		switch {
		case parsed.statusCode >= 500:
			c.status5xx++
		case parsed.statusCode >= 400:
			c.status4xx++
		}
		c.histogram.observe(parsed.durationMs)

		if window := c.siteFor(parsed.host); window != nil {
			window.requests++
			switch {
			case parsed.statusCode >= 500:
				window.status5xx++
			case parsed.statusCode >= 400:
				window.status4xx++
			}
			window.histogram.observe(parsed.durationMs)
		}
	}

	return err
}

// Sample closes the window and returns its RED metrics, then starts a new one.
// Returns nil if no time has passed, which would make every rate meaningless.
func (c *Collector) Sample(now time.Time) *RED {
	elapsed := now.Sub(c.lastSample).Seconds()
	if elapsed <= 0 {
		return nil
	}

	red := &RED{
		RequestsPerS:  float64(c.requests) / elapsed,
		Status4xxPerS: float64(c.status4xx) / elapsed,
		Status5xxPerS: float64(c.status5xx) / elapsed,
		Sites:         c.sampleSites(elapsed),
	}

	if c.requests > 0 {
		errorRate := float64(c.status5xx) / float64(c.requests) * 100
		red.ErrorRatePct = &errorRate

		if p50, ok := c.histogram.quantile(0.50); ok {
			red.P50Ms = &p50
		}
		if p95, ok := c.histogram.quantile(0.95); ok {
			red.P95Ms = &p95
		}
		if p99, ok := c.histogram.quantile(0.99); ok {
			red.P99Ms = &p99
		}
	}

	c.requests, c.status4xx, c.status5xx = 0, 0, 0
	c.histogram.reset()
	c.sites = make(map[string]*siteWindow)
	c.lastSample = now

	return red
}

// sampleSites closes every per-site window into a report, busiest first.
//
// At most maxReportedSites leave the machine; anything past the cut is summed
// into the overflow bucket rather than dropped, so the per-site rows always
// add back up to roughly the aggregate — a breakdown that quietly loses
// traffic would have the owner hunting for a site that does not exist.
func (c *Collector) sampleSites(elapsed float64) []SiteRED {
	// The overflow is assembled separately so the tracking-time bucket (a
	// scanner blowing past maxTrackedSites) and the report-time cut merge into
	// ONE row — two rows named "(other)" would collide in the platform's
	// (server, ts, host) uniqueness.
	overflow := SiteRED{Host: overflowSite}
	haveOverflow := false

	sites := make([]SiteRED, 0, len(c.sites))
	for host, window := range c.sites {
		if host == overflowSite {
			overflow.RequestsPerS += float64(window.requests) / elapsed
			overflow.Status4xxPerS += float64(window.status4xx) / elapsed
			overflow.Status5xxPerS += float64(window.status5xx) / elapsed
			haveOverflow = true
			continue
		}
		site := SiteRED{
			Host:          host,
			RequestsPerS:  float64(window.requests) / elapsed,
			Status4xxPerS: float64(window.status4xx) / elapsed,
			Status5xxPerS: float64(window.status5xx) / elapsed,
		}
		if window.requests > 0 {
			errorRate := float64(window.status5xx) / float64(window.requests) * 100
			site.ErrorRatePct = &errorRate
			if p50, ok := window.histogram.quantile(0.50); ok {
				site.P50Ms = &p50
			}
			if p95, ok := window.histogram.quantile(0.95); ok {
				site.P95Ms = &p95
			}
			if p99, ok := window.histogram.quantile(0.99); ok {
				site.P99Ms = &p99
			}
		}
		sites = append(sites, site)
	}

	sort.Slice(sites, func(i, j int) bool {
		if sites[i].RequestsPerS != sites[j].RequestsPerS {
			return sites[i].RequestsPerS > sites[j].RequestsPerS
		}
		return sites[i].Host < sites[j].Host // deterministic under equal load
	})

	if len(sites) > maxReportedSites {
		for _, site := range sites[maxReportedSites:] {
			overflow.RequestsPerS += site.RequestsPerS
			overflow.Status4xxPerS += site.Status4xxPerS
			overflow.Status5xxPerS += site.Status5xxPerS
		}
		sites = sites[:maxReportedSites]
		haveOverflow = true
	}

	// No percentiles for the overflow, ever: durations from unrelated sites
	// mixed together answer no question anyone is asking.
	if haveOverflow {
		sites = append(sites, overflow)
	}

	return sites
}

// Health describes anything the owner should know about the log itself,
// or an empty string if all is well. Reported once, not every window.
func (c *Collector) Health() string {
	if c.tailer.file == nil && !c.warnedUnreadable {
		c.warnedUnreadable = true
		return "cannot read the access log at " + c.tailer.path +
			" — request metrics will be blank until it exists and is readable by the onserva user"
	}
	if c.tailer.file != nil {
		c.warnedUnreadable = false
	}
	if c.skippedBytes > 0 {
		skipped := c.skippedBytes
		c.skippedBytes = 0
		return "access log is growing faster than it can be read — skipped " +
			formatBytes(skipped) + " of it, so request counts for that period are understated"
	}
	return ""
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return itoa(n) + " B"
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 3 {
		div *= unit
		exp++
	}
	return itoa(n/div) + string("KMG"[exp]) + "iB"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
