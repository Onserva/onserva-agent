//go:build linux

// Command onserva-agent reports one machine's health to the Onserva platform.
//
// It does three things and nothing else:
//   - reads statistics from /proc every 20 seconds
//   - posts them out over HTTPS with this server's own key
//   - keeps them in memory and retries if the platform cannot be reached
//
// It opens no ports, accepts no commands, and needs no privileges beyond
// reading files that are world-readable anyway. It runs as its own unprivileged
// user.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Onserva/onserva-agent/internal/backupstat"
	"github.com/Onserva/onserva-agent/internal/collect"
	"github.com/Onserva/onserva-agent/internal/config"
	"github.com/Onserva/onserva-agent/internal/containers"
	"github.com/Onserva/onserva-agent/internal/dbstat"
	"github.com/Onserva/onserva-agent/internal/fixes"
	"github.com/Onserva/onserva-agent/internal/httplog"
	"github.com/Onserva/onserva-agent/internal/spool"
	"github.com/Onserva/onserva-agent/internal/transport"
)

// version is stamped in at build time (see build.sh).
var version = "dev"

const (
	// The filesystem we report on. Phase 1 watches the root disk, which is where
	// servers actually run out of space.
	rootPath = "/"

	// Roughly four hours of samples at the default interval. Enough to ride out
	// a long platform outage; small enough that memory use stays trivial.
	bufferCapacity = 720

	// Samples sent per tick when catching up after an outage. Draining faster
	// than this would look like a runaway agent to the platform's rate guard.
	maxSendsPerTick = 8

	// Ceiling on the wait between retries when the platform is unreachable.
	maxBackoff = 5 * time.Minute

	// The unprivileged user the reporting half runs as. The executor looks up
	// its group to hand over the spool directory and nothing else.
	agentUser = "onserva"

	// How often to look for access logs again.
	//
	// Not every tick: the answer changes when somebody installs nginx, which is
	// not a twenty-second event, and five stat calls three times a minute for
	// the life of the machine is noise for nothing. Not once at startup either
	// — an agent installed before the proxy would then never notice, and the
	// button would stay hidden until someone thought to restart it.
	detectInterval = 30 * time.Minute
)

func main() {
	showVersion := flag.Bool("version", false, "print the agent version and exit")
	check := flag.Bool("check", false, "take one reading, send it once, and report what happened")
	execute := flag.Bool("execute-fixes", false,
		"carry out authorised actions left in the spool, then exit (run as root by onserva-fix.service)")
	flag.Parse()

	if *showVersion {
		fmt.Println("onserva-agent", version)
		return
	}

	// The privileged half. It reads no configuration, needs no key, and never
	// learns where the platform is — see execute.go.
	if *execute {
		os.Exit(runExecutor())
	}

	log.SetFlags(0) // systemd's journal adds its own timestamps

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("onserva-agent: %v", err)
	}

	// Optional: only servers running a reverse proxy have request metrics.
	//
	// Two ways to switch them on, and the environment wins. Someone who has
	// written ONSERVA_ACCESS_LOG into a systemd unit has said exactly what they
	// want; a settings file written by a button should not quietly override it.
	var accessLog *httplog.Collector
	source, activeID := "", ""
	if cfg.AccessLogPath != "" {
		accessLog = httplog.New(cfg.AccessLogPath, httplog.Format(cfg.AccessLogFormat), time.Now())
		source = cfg.AccessLogPath + " (from ONSERVA_ACCESS_LOG)"
	} else if candidate, ok := httplog.Enabled(); ok {
		accessLog = httplog.New(candidate.Path, candidate.Format, time.Now())
		source = candidate.Path + " (" + candidate.Label + ", switched on from the dashboard)"
		activeID = candidate.ID
	}

	collector, err := collect.New(version, rootPath, accessLog)
	if err != nil {
		log.Fatalf("onserva-agent: cannot read system statistics: %v", err)
	}

	// Database readings, for the engines the owner has switched on. The
	// sampler holds no credentials — see internal/dbstat — and an empty
	// enabled set means it does nothing at all.
	databases := dbstat.NewCollector()
	if enabled := databases.SetEnabled(dbstat.Enabled()); len(enabled) > 0 {
		for _, id := range enabled {
			log.Printf("onserva-agent: database monitoring is on for %s", id)
		}
	}
	collector.AttachDatabases(databases)
	// Container visibility needs no switch: it is the same class of fact as
	// process counts, from the same world-readable /proc.
	collector.AttachContainers(containers.NewCollector())

	client := transport.New(cfg.IngestURL, cfg.Token, version)

	if *check {
		os.Exit(runCheck(collector, client))
	}

	log.Printf("onserva-agent %s starting · reporting to %s every %s · key %s",
		version, cfg.IngestURL, cfg.Interval, config.Redacted(cfg.Token))
	if source != "" {
		log.Printf("onserva-agent: reading request metrics from %s", source)
	} else {
		log.Print("onserva-agent: no access log configured — request metrics will not be reported")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	run(ctx, &agent{
		collector: collector,
		client:    client,
		databases: databases,
		interval:  cfg.Interval,
		queue:     newBuffer(bufferCapacity),
		// Set only when the environment named a log, in which case a dashboard
		// switch must not override it.
		envAccessLog: cfg.AccessLogPath,
		accessLogID:  activeID,
	})

	log.Print("onserva-agent: stopped")
}

// ─── the agent loop ─────────────────────────────────────────────────────────

type agent struct {
	collector *collect.Collector
	client    *transport.Client
	queue     *buffer
	interval  time.Duration

	// requested is the cadence the platform last asked for, if any.
	requested time.Duration

	// pendingResults are outcomes the executor has written and the platform has
	// not yet been told about. Held in memory rather than left in the spool
	// because a result read but not delivered would be reported again on the
	// next check-in — and an audit log claiming a service was restarted four
	// times when it was restarted once is worse than no audit log.
	//
	// They are lost if the process dies before delivering them. That is the
	// safe direction: the platform still knows it dispatched the action and can
	// say so, whereas a duplicated outcome is a lie it cannot detect.
	pendingResults []spool.Result

	// databases is the sampler the collector reads through; held here too so
	// the tick can refresh its enabled set from the settings file.
	databases *dbstat.Collector

	// pendingCandidates is the access-log survey waiting to go out, and
	// nextDetect is when to take it again. Cleared on a successful send like
	// the results above, so the platform is told once per survey rather than
	// three times a minute forever. pendingDatabases is the database survey,
	// on the same clock and the same pointer contract.
	pendingCandidates *[]httplog.Found
	pendingDatabases  *[]dbstat.Found
	pendingBackups    *[]backupstat.Found
	nextDetect        time.Time

	// envAccessLog is ONSERVA_ACCESS_LOG, empty unless an operator set it. When
	// it is set, the dashboard switch is ignored — an explicit unit file beats
	// a button, and silently overriding one would be a nasty surprise.
	envAccessLog string
	// accessLogID is the candidate currently being read, "" for none. Compared
	// against the settings file each tick so an authorised switch takes effect
	// without waiting for a restart.
	accessLogID string

	consecutiveFailures int
	nextAttempt         time.Time
	loggedOutage        bool
}

// envelope is a sample plus anything the agent has to say alongside it.
//
// Sample is embedded, so the wire format is unchanged for every field the
// platform already reads — everything here is simply additional, and absent on
// the overwhelming majority of check-ins.
//
// log_candidates is not a reading, which is why it lives here rather than in
// collect.Sample: it is the agent answering "which access logs exist on this
// machine, and can I read them?" so the dashboard can offer to switch request
// metrics on instead of telling the owner to go and edit a systemd unit.
type envelope struct {
	collect.Sample
	FixResults []spool.Result `json:"fix_results,omitempty"`

	// Minutes this machine's clock sits ahead of UTC (UTC+1 → 60), refreshed
	// every check-in so daylight-saving changes follow within a minute. It is
	// what lets a housekeeping schedule's "daily at 03:00" mean 3am HERE.
	// A pointer so UTC itself (0) is still sent rather than omitted.
	TzOffsetMinutes *int `json:"tz_offset_minutes,omitempty"`

	// A POINTER to the slice, and that is load-bearing. `omitempty` on a plain
	// slice omits an EMPTY one, which would make "I looked and this machine has
	// no access log" indistinguishable from "I never looked" — and the platform
	// reads a missing value as an agent too old to know about the feature. The
	// dashboard would then tell the owner to update an agent that was already
	// current, which is the exact bug this whole phase set out to remove.
	//
	// nil pointer  → field omitted   (no survey this tick)
	// &[]          → sends `[]`      (surveyed, found nothing)
	LogCandidates *[]httplog.Found `json:"log_candidates,omitempty"`

	// Which database engines exist on this machine — same survey contract,
	// same pointer semantics, same clock as the access-log survey.
	DBCandidates *[]dbstat.Found `json:"db_candidates,omitempty"`

	// Which backup locations exist and how fresh they are — same contract.
	BackupCandidates *[]backupstat.Found `json:"backup_candidates,omitempty"`
}

func run(ctx context.Context, a *agent) {
	// The first tick is one interval away, which is exactly what the collector
	// needs: processor use and network throughput are rates, and a rate needs
	// two readings.
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			a.tick(ctx)

			// The platform can change our cadence from its side, so a fleet can
			// be turned down without touching a single machine.
			if a.interval != a.pendingInterval() {
				a.interval = a.pendingInterval()
				ticker.Reset(a.interval)
				log.Printf("onserva-agent: reporting interval is now %s", a.interval)
			}
		}
	}
}

func (a *agent) tick(ctx context.Context) {
	sample, err := a.collector.Sample()
	if err != nil {
		// A failed reading is worth saying out loud but is never fatal: the
		// next tick may well succeed, and an agent that exits is an agent that
		// stops watching.
		log.Printf("onserva-agent: could not take a reading: %v", err)
		return
	}

	if dropped := a.queue.push(sample); dropped {
		log.Print("onserva-agent: buffer full — discarded the oldest unsent reading")
	}

	// Said once when the condition starts, not every twenty seconds.
	if health := a.collector.AccessLogHealth(); health != "" {
		log.Printf("onserva-agent: %s", health)
	}
	for _, note := range a.collector.DatabaseNotes() {
		log.Printf("onserva-agent: %s", note)
	}

	a.surveyLogs()
	a.applyRequestMetricsSetting()
	a.applyDBMetricsSetting()
	a.collectResults()
	a.flush(ctx)
}

// applyDBMetricsSetting refreshes which engines are monitored from the
// settings file, so an authorised switch takes effect within a tick — the
// same contract as applyRequestMetricsSetting, minus the environment override
// (there is no ONSERVA_DB equivalent to defer to).
func (a *agent) applyDBMetricsSetting() {
	for _, id := range a.databases.SetEnabled(dbstat.Enabled()) {
		log.Printf("onserva-agent: database monitoring switched on for %s", id)
	}
}

// applyRequestMetricsSetting starts reading an access log the owner has just
// authorised, without waiting for a restart.
//
// One small read of a settings file per tick. The alternative — having the
// executor restart the agent — would mean the privileged half killing the
// process that holds the platform key, to apply a setting. This is cheaper and
// very much duller.
func (a *agent) applyRequestMetricsSetting() {
	if a.envAccessLog != "" {
		return // an operator said exactly what they wanted; leave it alone
	}

	candidate, enabled := httplog.Enabled()
	switch {
	case enabled && candidate.ID != a.accessLogID:
		a.collector.SetAccessLog(httplog.New(candidate.Path, candidate.Format, time.Now()))
		a.accessLogID = candidate.ID
		log.Printf("onserva-agent: request metrics switched on — reading %s's access log at %s",
			candidate.Label, candidate.Path)

	case !enabled && a.accessLogID != "":
		// The settings file went away. Stop reporting rather than keep reading
		// a log nobody has asked us to read since.
		a.collector.SetAccessLog(nil)
		a.accessLogID = ""
		log.Print("onserva-agent: request metrics switched off")
	}
}

// surveyLogs re-checks which access logs exist, on its own slow clock.
//
// Deliberately does no more than look: existence and whether this process can
// open the file. Nothing is read, and nothing is switched on — turning request
// metrics on is an action the owner authorises, not something the agent
// decides because it found a log lying around.
func (a *agent) surveyLogs() {
	if time.Now().Before(a.nextDetect) {
		return
	}
	found := httplog.Detect()
	a.pendingCandidates = &found
	// The database survey shares the clock: both answer "what is on this
	// machine now", and both change on the timescale of somebody installing
	// software. dbstat.Detect knocks on each engine's socket, which is
	// another reason it runs three times an hour and not three times a minute.
	databases := dbstat.Detect()
	a.pendingDatabases = &databases
	// And the backup locations, which change on the same "someone installed
	// something" timescale.
	backups := backupstat.Detect(time.Now())
	a.pendingBackups = &backups
	a.nextDetect = time.Now().Add(detectInterval)
}

// collectResults picks up whatever the privileged half has finished.
//
// A failure here is logged and shrugged off: not being able to read the spool
// must never stop readings going out, because monitoring is the job and fixing
// is the extra.
func (a *agent) collectResults() {
	results, err := spool.TakeResults()
	if err != nil {
		log.Printf("onserva-agent: could not read fix results: %v", err)
		return
	}
	for _, result := range results {
		outcome := "failed"
		if result.OK {
			outcome = "succeeded"
		}
		log.Printf("onserva-agent: authorised action %s %s", result.ID, outcome)
	}
	a.pendingResults = append(a.pendingResults, results...)
}

func (a *agent) flush(ctx context.Context) {
	if time.Now().Before(a.nextAttempt) {
		return // still backing off
	}

	for sent := 0; sent < maxSendsPerTick; sent++ {
		sample, ok := a.queue.peek()
		if !ok {
			break
		}

		// Results and the log survey ride along with the reading, and are only
		// let go of once the platform has actually taken them.
		_, tzSeconds := time.Now().Zone()
		tzMinutes := tzSeconds / 60
		response, err := a.client.Send(ctx, envelope{
			Sample:           sample,
			FixResults:       a.pendingResults,
			LogCandidates:    a.pendingCandidates,
			DBCandidates:     a.pendingDatabases,
			BackupCandidates: a.pendingBackups,
			TzOffsetMinutes:  &tzMinutes,
		})
		if err != nil {
			a.handleSendError(err)
			return
		}

		a.pendingResults = nil
		a.pendingCandidates = nil
		a.pendingDatabases = nil
		a.pendingBackups = nil
		a.queue.pop()
		a.onSuccess(response)
	}
}

func (a *agent) handleSendError(err error) {
	sendErr, ok := err.(*transport.SendError)
	if !ok {
		sendErr = &transport.SendError{Retryable: true, Message: err.Error()}
	}

	if !sendErr.Retryable {
		// This sample will never be accepted. Drop it rather than let it block
		// every reading behind it.
		a.queue.pop()
		log.Printf("onserva-agent: discarded a reading the platform rejected — %v", sendErr)
		return
	}

	a.consecutiveFailures++
	wait := a.backoff(sendErr.RetryAfter)
	a.nextAttempt = time.Now().Add(wait)

	// Log the start of an outage and its end, not every attempt in between —
	// otherwise a night-long outage fills the journal.
	if !a.loggedOutage {
		a.loggedOutage = true
		log.Printf("onserva-agent: cannot reach the platform (%v) — buffering readings, retrying in %s",
			sendErr, wait.Round(time.Second))
	}
}

func (a *agent) onSuccess(response transport.Response) {
	if a.loggedOutage {
		log.Printf("onserva-agent: platform reachable again — %d readings still to send", a.queue.len())
		a.loggedOutage = false
	}
	a.consecutiveFailures = 0
	a.nextAttempt = time.Time{}

	if response.NextIntervalSeconds > 0 {
		a.requested = config.ClampInterval(time.Duration(response.NextIntervalSeconds) * time.Second)
	}

	a.spoolAuthorised(response.AuthorisedFixes)
}

// spoolAuthorised hands approved work to the privileged half.
//
// This process does no more than write a file. It does not check whether the
// action is sensible, because it is not the component that gets to decide —
// the executor validates the key and the target again with its own compiled-in
// list before anything runs. What is rejected here is only what could not be
// written safely at all: an id that would escape the spool directory.
func (a *agent) spoolAuthorised(authorised []transport.AuthorisedFix) {
	for _, fix := range authorised {
		err := spool.Write(spool.Request{
			ID:     fix.ID,
			Action: fixes.Key(fix.Action),
			Target: fix.Target,
		})
		if err != nil {
			// Worth saying loudly: the owner pressed a button and this is the
			// reason nothing will happen.
			log.Printf("onserva-agent: declined authorised action %s (%s on %q): %v",
				fix.ID, fix.Action, fix.Target, err)
			continue
		}
		log.Printf("onserva-agent: queued authorised action %s (%s on %q) for the executor",
			fix.ID, fix.Action, fix.Target)
	}
}

// pendingInterval is the cadence we should be running at: whatever the platform
// last asked for, or our own if it has not asked.
func (a *agent) pendingInterval() time.Duration {
	if a.requested == 0 {
		return a.interval
	}
	return a.requested
}

// backoff doubles the wait on each consecutive failure, up to maxBackoff, and
// always honours an explicit Retry-After from the platform.
func (a *agent) backoff(retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	wait := a.interval
	for i := 1; i < a.consecutiveFailures && wait < maxBackoff; i++ {
		wait *= 2
	}
	if wait > maxBackoff {
		wait = maxBackoff
	}
	return wait
}

// ─── one-shot check, used by the installer ──────────────────────────────────

func runCheck(collector *collect.Collector, client *transport.Client) int {
	fmt.Println("Taking a reading…")
	time.Sleep(2 * time.Second) // the collector needs two points to measure a rate

	sample, err := collector.Sample()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read system statistics: %v\n", err)
		return 1
	}
	fmt.Println("  " + collector.Describe(sample))

	fmt.Println("Sending it to Onserva…")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Send(ctx, sample); err != nil {
		fmt.Fprintf(os.Stderr, "  Failed: %v\n", err)
		return 1
	}

	fmt.Println("  Accepted. This server is now reporting to Onserva.")
	return 0
}
