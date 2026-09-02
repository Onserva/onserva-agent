# The Onserva agent

A single Go program that runs on a monitored server and reports its health. It is the client half of
[Onserva](https://onserva.com), which watches servers and explains what is wrong in plain English.

It is deliberately the least interesting program we write, and that is the point: it is installed on
machines we do not own, sometimes for clients who will want to satisfy themselves about what it does
before they let it near their business. So it is published here to be read.

No third-party dependencies, no open ports, no credentials, no privileges. Around six thousand
lines of standard-library Go, plus two thousand of tests — readable in an afternoon, and the four
sections below on what it *cannot* do are the ones worth reading first.

## What it does

Every 20 seconds it reads the machine's own kernel counters and posts them to Onserva over HTTPS.

| Reading                | Where it comes from                                        |
| ---------------------- | ---------------------------------------------------------- |
| Processor use          | `/proc/stat`, as a difference between two readings          |
| Waiting on disk        | `/proc/stat` — the `iowait` share, tracked separately       |
| Memory use             | `/proc/meminfo` (`MemTotal` minus `MemAvailable`)           |
| Cached memory          | `/proc/meminfo` — reclaimable, excluded from "used"         |
| Swap in use            | `/proc/meminfo` (`SwapTotal` minus `SwapFree`)              |
| Disk space             | `statfs()` on `/`                                           |
| File slots (inodes)    | `statfs()` — absent on filesystems that allocate on demand   |
| Disk reads/writes      | `/proc/diskstats`, physical devices only, as a rate         |
| Network throughput     | `/proc/net/dev`, converted to a rate                        |
| Network errors & drops | `/proc/net/dev`, as a rate                                  |
| Open connections       | `/proc/net/sockstat` — a 4-line summary, not per-connection |
| Queue length           | `/proc/loadavg` (1, 5 and 15 minute)                        |
| Uptime                 | `/proc/uptime`                                              |

Two deliberate choices in there. Connections come from `sockstat` rather than `/proc/net/tcp`, because the
latter is one line per connection and would mean parsing tens of thousands of lines every twenty seconds
on a busy server — an agent that measurably loads the machine it is watching has defeated its own purpose.
And partitions are excluded from disk activity, because their operations are already counted against the
whole device.

**What it cannot see.** Database, cache and queue internals belong to those services and need
credentials to read. That is a different security posture from the one described below, and it is a
decision rather than an oversight.

## Request metrics (RED), from the reverse proxy

Optionally, the agent also reports what your *websites* are doing: **R**ate, **E**rrors and
**D**uration.

| Reading           | Meaning                                                        |
| ----------------- | -------------------------------------------------------------- |
| Requests / second | How much traffic the sites are handling                          |
| 5xx / second, and % | Requests the server failed to answer — your problem            |
| 4xx / second      | Requests for things that do not exist — usually not your problem |
| p50 / p95 / p99   | Response time: typical, slow, and worst-case                     |

### Nothing about your visitors leaves the machine

The agent reads the access log **on the server**, counts requests, bins response times into a fixed
histogram, and sends numbers. Paths, IP addresses, user agents and referrers are parsed past and
discarded. An access log is full of personal data — who asked for what, and when — and shipping it to a
monitoring service would create a data-protection problem where none needs to exist. None of it is
required to answer "is the site up, and is it fast".

Percentiles are computed from a ~30-bucket histogram, so they are accurate to roughly the bucket width
rather than exact. That is deliberate: keeping every response time would mean the agent's memory growing
with the traffic it is watching.

### Turning it on

Traefik does **not** write an access log by default, and in a Coolify install it usually logs to stdout —
which Docker captures to a root-only file. The agent does not run as root, so the log needs to go
somewhere it can read.

**1. Make Traefik write the log to a file.** Add to its static configuration:

```yaml
accessLog:
  filePath: /var/log/traefik/access.log
  format: json
```

or, as command-line flags:

```
--accesslog=true
--accesslog.filepath=/var/log/traefik/access.log
--accesslog.format=json
```

**2. Mount that directory to the host** so it survives container restarts, e.g.
`/data/coolify/proxy/logs:/var/log/traefik`. On a Coolify host, Traefik is defined in the proxy's own
compose file — check the exact path on your box before editing it.

**3. Point the agent at the host-side path** when installing:

```bash
curl -fsSL https://app.onserva.com/install.sh | sudo bash -s -- \
  --token onsv_xxx \
  --url https://app.onserva.com/api/ingest \
  --access-log /data/coolify/proxy/logs/access.log
```

The installer adds the `onserva` user to the log file's group rather than loosening its permissions, so
the agent gets to read that one file and nothing about the proxy's setup changes. If the log is
root-only it says so and tells you the two commands to fix it.

`json` is strongly preferred over `clf` — it is unambiguous, and it carries the status Traefik actually
returned to the client, which is what you need when a backend is down and Traefik answers 502 on its
behalf. Both are supported; `auto` detects per line.

**Rotation, truncation and restarts are handled.** The agent follows the file across `logrotate`,
re-reads from zero when the file is replaced, keeps its place across a transient failure so nothing is
counted twice, and holds back half-written lines. It starts at the end of an existing log rather than
parsing a gigabyte of history on boot. If the log grows faster than it can be drained it skips ahead and
says so in the journal, rather than quietly under-reporting.

**No log, no problem.** A server without a reverse proxy reports nothing here, the dashboard says so
explicitly rather than drawing a flat line at zero, and every other metric is unaffected.

## What it does not do

- **It opens no port.** Every connection is outbound. Installing it creates no new way into the
  machine, which is what makes it safe behind a client's firewall without asking them to change
  anything.
- **It accepts no commands.** In Phase 1 it only sends. (Phase 3 adds a *pull* model — it asks
  Onserva whether the owner has authorised anything, and may only run actions from a fixed list.)
- **It has no dependencies.** No third-party Go packages at all: everything is the standard library
  or in this folder. There is no supply chain to compromise and nothing to keep patched.
- **It needs no privileges.** It runs as its own unprivileged `onserva` user with no shell, no home
  directory and no capabilities, reading files that are world-readable anyway.

## Building

Requires Go 1.24 or newer.

```bash
./build.sh
```

Produces static binaries for 64-bit Intel/AMD and ARM in `dist/`, each with a SHA-256 checksum, plus
a copy of the systemd unit. Static means one file runs on Ubuntu, Debian, Alma or Alpine alike.

The installer verifies a binary's SHA-256 against the published checksum before it will run anything,
so a build you publish yourself must ship its `.sha256` alongside it.

For a single binary without the cross-compilation, on Linux:

```bash
go install github.com/Onserva/onserva-agent/cmd/onserva-agent@latest
```

## Installing

The dashboard generates the command when you create a server. The installer is served from
[`https://app.onserva.com/install.sh`](https://app.onserva.com/install.sh) rather than living in this
repository, because it has to be served over HTTPS to be pasted into a terminal. Read it before you
run it — it is served as plain text precisely so that anyone can.

Note the **`app.`** host. The apex serves the marketing site; the installer and the ingest endpoint
are both on `app.onserva.com`.

## Configuration

Read from the environment only, so the key never appears in the process list. systemd supplies it
from `/etc/onserva/agent.env`, which is readable by root and the agent's own user and nobody else.

| Variable                     | Required | Meaning                                          |
| ---------------------------- | -------- | ------------------------------------------------ |
| `PLATFORM_INGEST_URL`        | yes      | Where to post readings. Must be HTTPS.           |
| `SERVER_AGENT_TOKEN`         | yes      | This server's key. Starts `onsv_`.               |
| `ONSERVA_INTERVAL_SECONDS`   | no       | Defaults to 20. Clamped to 5s–10m.               |
| `ONSERVA_ACCESS_LOG`         | no       | Reverse proxy access log. Blank disables RED.    |
| `ONSERVA_ACCESS_LOG_FORMAT`  | no       | `auto` (default), `json` or `clf`.               |

Onserva can also change the interval from its side, in its reply to each reading — so a whole fleet
can be turned down without touching a single machine.

## When the network fails

Readings keep being taken and are held in memory (about four hours' worth). As soon as the platform
is reachable the backlog goes out in order, oldest first. Retries back off from 20 seconds up to five
minutes, and the outage is logged once at the start and once at the end rather than every attempt.

Because Onserva treats a reading's timestamp as unique per server, a reading that is sent twice is
stored once. Nothing is ever double-counted.

## Checking it

```bash
onserva-agent --version
onserva-agent --check     # takes one reading, sends it once, says what happened
systemctl status onserva-agent
journalctl -u onserva-agent -f
```

`--check` is what the installer runs before it starts the service, so an install that would not have
worked fails visibly rather than leaving you with a server you *think* is being watched.

## Layout

```
cmd/onserva-agent/    the loop, the buffer, and the two command-line flags
internal/config/      loads and validates the environment
internal/collect/     reads /proc — the only place that knows about Linux internals
internal/httplog/     tails the access log and turns it into RED metrics
internal/transport/   posts to the platform, and decides what is worth retrying
deploy/               the systemd unit (hardened; read the comments)
build.sh              cross-compiles and checksums
```

Linux only. The `/proc` filesystem is Linux's, and `go build` on any other platform will say so.

## Tests

```bash
go test ./...
```

`internal/httplog` is deliberately portable so its tests run anywhere. The file-tailing tests —
rotation, truncation, partial writes — are skipped on Windows, which refuses to rename a file another
handle holds open. Run the full set on Linux:

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.26 go test ./internal/httplog/
```

## Licence

[Apache License 2.0](LICENSE) — © No Fear Tech Ltd.

You may read it, run it, fork it and modify it. If you are evaluating Onserva and want to satisfy
yourself about what runs on your machines, that is exactly what this repository is for.
