//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/Onserva/onserva-agent/internal/dbstat"
	"github.com/Onserva/onserva-agent/internal/fixes"
	"github.com/Onserva/onserva-agent/internal/httplog"
	"github.com/Onserva/onserva-agent/internal/spool"
)

// The privileged half of the agent.
//
// Run by onserva-fix.service as root, woken by onserva-fix.path when the
// unprivileged agent spools an authorised action. It reads the request, decides
// for itself whether it is willing to carry it out, runs it, writes the outcome
// and exits. It never opens a socket, never reads the agent's key, and never
// learns the platform's address — its unit runs with PrivateNetwork=true, so it
// could not reach the internet if it tried.
//
// That is the trade being made for the ability to restart a program: rather
// than giving the network-facing process a privilege, a second process with the
// privilege is kept deaf to the network. If the agent is compromised through
// the platform, the most it can do is ask this program to restart something
// named — which is exactly the bounded action the owner authorised.

const (
	// A restart that has not finished by now is not going to. Bounded so a
	// wedged unit cannot leave the executor running forever holding root.
	commandTimeout = 60 * time.Second

	// Enough of the command's own words to be useful in the audit log without
	// letting a chatty unit push a novel into the database.
	maxDetail = 1000
)

func runExecutor() int {
	log.SetFlags(0)

	gid := agentGroupID()
	if err := spool.Ensure(gid); err != nil {
		log.Printf("onserva-fix: cannot prepare %s: %v", spool.Root, err)
		return 1
	}

	requests, err := spool.TakeRequests()
	if err != nil {
		// Reported, not fatal: the readable requests in the same batch still
		// deserve to run.
		log.Printf("onserva-fix: %v", err)
	}
	if len(requests) == 0 {
		return 0
	}

	for _, request := range requests {
		result := carryOut(request)
		if err := spool.WriteResult(result, gid); err != nil {
			log.Printf("onserva-fix: could not record the outcome of %s: %v", request.ID, err)
		}
	}
	return 0
}

// carryOut performs one authorised action, and always produces a result.
//
// Every refusal is reported rather than swallowed. An authorisation that
// quietly did nothing is the worst outcome available: the owner pressed a
// button, watched nothing happen, and has no idea why.
func carryOut(request spool.Request) spool.Result {
	now := time.Now().UTC()

	if !request.Fresh(now) {
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: now,
			Detail: fmt.Sprintf(
				"Not carried out: this authorisation was more than %s old by the time it reached the server, so it was allowed to lapse rather than acted on late.",
				spool.MaxAge),
		}
	}

	// The executor decides for itself. The request is a proposal, not an
	// instruction, and this is where the allowlist is actually enforced.
	command, err := fixes.Plan(request.Action, request.Target)
	if err != nil {
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: now,
			Detail: "Not carried out: " + err.Error() + ".",
		}
	}

	log.Printf("onserva-fix: %s (authorisation %s)", command.What, request.ID)

	// Not every allowlisted action runs a program. This one writes a settings
	// file and starts nothing, which is why it is handled here rather than
	// squeezed into a command line.
	if command.Kind == fixes.KindEnableRequestMetrics {
		if _, err := httplog.Enable(command.CandidateID, agentGroupID()); err != nil {
			return spool.Result{
				ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
				Detail: "Not carried out: " + err.Error() + ".",
			}
		}
		return spool.Result{
			ID: request.ID, OK: true, FinishedAt: time.Now().UTC(),
			Detail: "Done — " + command.What +
				". It will start appearing on the dashboard within a minute or two.",
		}
	}

	if command.Kind == fixes.KindEnableDBMetrics {
		if _, err := dbstat.Enable(command.EngineID, agentGroupID()); err != nil {
			return spool.Result{
				ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
				Detail: "Not carried out: " + err.Error() + ".",
			}
		}
		return spool.Result{
			ID: request.ID, OK: true, FinishedAt: time.Now().UTC(),
			Detail: "Done — " + command.What +
				". Readings will start appearing on the dashboard within a minute or two.",
		}
	}

	if command.Kind == fixes.KindDisableRequestMetrics {
		if err := httplog.Disable(); err != nil {
			return spool.Result{
				ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
				Detail: "Not carried out: " + err.Error() + ".",
			}
		}
		return spool.Result{
			ID: request.ID, OK: true, FinishedAt: time.Now().UTC(),
			Detail: "Done — " + command.What + ".",
		}
	}

	if command.Kind == fixes.KindPurgeSwap {
		return executePurgeSwap(request, command)
	}

	if command.Kind == fixes.KindDisableDBMetrics {
		if _, err := dbstat.Disable(command.EngineID, agentGroupID()); err != nil {
			return spool.Result{
				ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
				Detail: "Not carried out: " + err.Error() + ".",
			}
		}
		return spool.Result{
			ID: request.ID, OK: true, FinishedAt: time.Now().UTC(),
			Detail: "Done — " + command.What + ".",
		}
	}

	// A plan may carry its own bound (database maintenance outlives a restart's
	// sixty seconds); the default still holds for everything that does not.
	timeout := commandTimeout
	if command.Timeout > 0 {
		timeout = command.Timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Arguments as a slice, never a shell string — which is what makes the
	// target's own characters inert rather than merely unusual.
	output, runErr := exec.CommandContext(ctx, command.Path, command.Args...).CombinedOutput()
	said := clip(strings.TrimSpace(string(output)), maxDetail)
	finished := time.Now().UTC()

	if ctx.Err() != nil {
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: finished,
			Detail: fmt.Sprintf("Gave up after %s waiting for this to finish. %s", timeout, said),
		}
	}
	if runErr != nil {
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: finished,
			Detail: strings.TrimSpace(fmt.Sprintf("Failed: %v. %s", runErr, said)),
		}
	}

	detail := "Done — " + command.What + "."
	if said != "" {
		detail += " " + said
	}
	return spool.Result{ID: request.ID, OK: true, FinishedAt: finished, Detail: clip(detail, maxDetail)}
}

// executePurgeSwap empties parked swap back into RAM: guard, swapoff, swapon.
//
// The guard is judged HERE, at execution time, against the machine's memory
// figures as they are now — the moment of authorisation may be minutes or,
// for a scheduled run, a week in the past. Refusing is a first-class outcome
// with a sentence the owner can act on, never a gamble taken on their behalf.
func executePurgeSwap(request spool.Request, command fixes.Command) spool.Result {
	meminfo, readErr := os.ReadFile("/proc/meminfo")
	if readErr != nil {
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
			Detail: "Not carried out: this machine's memory figures could not be read.",
		}
	}
	ok, usedKB, verdict := fixes.SwapPurgeVerdict(string(meminfo))
	if !ok {
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
			Detail: "Not carried out: " + verdict + ".",
		}
	}

	swapoff, offErr := exec.LookPath("swapoff")
	swapon, onErr := exec.LookPath("swapon")
	if offErr != nil || onErr != nil {
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
			Detail: "Not carried out: this machine does not have the swap tools installed.",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), command.Timeout)
	defer cancel()

	if output, err := exec.CommandContext(ctx, swapoff, "-a").CombinedOutput(); err != nil {
		said := clip(strings.TrimSpace(string(output)), maxDetail)
		// swapoff failed partway: re-arm what we can before reporting, so a
		// failed purge never leaves the machine without its reserve.
		_ = exec.Command(swapon, "-a").Run()
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
			Detail: strings.TrimSpace(fmt.Sprintf(
				"The purge could not complete and the reserve was re-armed: %v. %s", err, said)),
		}
	}
	if output, err := exec.CommandContext(ctx, swapon, "-a").CombinedOutput(); err != nil {
		said := clip(strings.TrimSpace(string(output)), maxDetail)
		return spool.Result{
			ID: request.ID, OK: false, FinishedAt: time.Now().UTC(),
			Detail: strings.TrimSpace(fmt.Sprintf(
				"Parked memory was moved back into RAM, but re-arming the swap failed: %v. %s — "+
					"the machine currently has NO emergency reserve and needs a person to run swapon", err, said)),
		}
	}

	detail := "Done — " + command.What + "."
	if usedKB > 0 {
		detail = fmt.Sprintf("Done — moved %d MB of parked memory back into RAM and re-armed the reserve.", usedKB/1024)
	} else {
		detail = "Done — nothing was parked; the reserve was re-armed clean."
	}
	return spool.Result{ID: request.ID, OK: true, FinishedAt: time.Now().UTC(), Detail: detail}
}

// agentGroupID finds the unprivileged agent's group, so the spool directories
// can be handed to it precisely rather than opened to everyone.
//
// Returns -1 when the group is not there — which happens on a machine where the
// executor was installed but the agent was not. The directories are still
// created, root-only, and the executor simply never has anything to do.
func agentGroupID() int {
	group, err := user.LookupGroup(agentUser)
	if err != nil {
		log.Printf("onserva-fix: no %q group on this machine — the spool will be root-only", agentUser)
		return -1
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return -1
	}
	return gid
}

func clip(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
