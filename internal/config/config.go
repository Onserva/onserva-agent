// Package config loads and validates the agent's settings.
//
// Configuration comes from the environment only — systemd supplies it from
// /etc/onserva/agent.env, which is readable by the agent's own user and nobody
// else. Nothing is ever read from a command-line argument, so the token cannot
// appear in the process list.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultInterval matches the platform's expectation. The platform can move
	// it at runtime via next_interval_seconds in its response.
	DefaultInterval = 20 * time.Second

	MinInterval = 5 * time.Second
	MaxInterval = 10 * time.Minute
)

type Config struct {
	IngestURL string
	Token     string
	Interval  time.Duration

	// AccessLogPath is the reverse proxy's access log, or "" to skip request
	// metrics entirely. Optional by design: most servers do not run a proxy,
	// and the agent must be useful on them regardless.
	AccessLogPath string
	// AccessLogFormat is "auto", "json" or "clf".
	AccessLogFormat string
}

// Load reads the environment and fails loudly on anything missing or malformed.
// A misconfigured agent must never start and quietly report nothing.
func Load() (Config, error) {
	cfg := Config{
		IngestURL:       strings.TrimSpace(os.Getenv("PLATFORM_INGEST_URL")),
		Token:           strings.TrimSpace(os.Getenv("SERVER_AGENT_TOKEN")),
		Interval:        DefaultInterval,
		AccessLogPath:   strings.TrimSpace(os.Getenv("ONSERVA_ACCESS_LOG")),
		AccessLogFormat: strings.ToLower(strings.TrimSpace(os.Getenv("ONSERVA_ACCESS_LOG_FORMAT"))),
	}
	if cfg.AccessLogFormat == "" {
		cfg.AccessLogFormat = "auto"
	}

	var problems []string

	if cfg.IngestURL == "" {
		problems = append(problems, "PLATFORM_INGEST_URL is not set")
	} else {
		parsed, err := url.Parse(cfg.IngestURL)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("PLATFORM_INGEST_URL is not a valid URL: %v", err))
		case parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1":
			// Metrics are not secret, but the bearer token in the header is.
			// Plain HTTP is allowed only against a local development server.
			problems = append(problems, "PLATFORM_INGEST_URL must use https")
		case parsed.Host == "":
			problems = append(problems, "PLATFORM_INGEST_URL has no host")
		}
	}

	if cfg.Token == "" {
		problems = append(problems, "SERVER_AGENT_TOKEN is not set")
	} else if !strings.HasPrefix(cfg.Token, "onsv_") {
		problems = append(problems, "SERVER_AGENT_TOKEN does not look like an Onserva key (should start with onsv_)")
	}

	if raw := strings.TrimSpace(os.Getenv("ONSERVA_INTERVAL_SECONDS")); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil {
			problems = append(problems, "ONSERVA_INTERVAL_SECONDS must be a whole number of seconds")
		} else {
			cfg.Interval = ClampInterval(time.Duration(seconds) * time.Second)
		}
	}

	switch cfg.AccessLogFormat {
	case "auto", "json", "clf":
	default:
		problems = append(problems, "ONSERVA_ACCESS_LOG_FORMAT must be auto, json or clf")
	}

	if len(problems) > 0 {
		return Config{}, errors.New("configuration is invalid:\n  - " + strings.Join(problems, "\n  - ") +
			"\n\nCheck /etc/onserva/agent.env")
	}

	return cfg, nil
}

// ClampInterval keeps a platform-supplied interval inside sane bounds, so a bad
// value cannot turn the fleet into a denial-of-service attack on ourselves, or
// silence it completely.
func ClampInterval(d time.Duration) time.Duration {
	if d < MinInterval {
		return MinInterval
	}
	if d > MaxInterval {
		return MaxInterval
	}
	return d
}

// Redacted returns the token with all but its prefix removed, for logging.
func Redacted(token string) string {
	if len(token) <= 12 {
		return "onsv_…"
	}
	return token[:12] + "…"
}
