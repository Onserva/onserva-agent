// Package transport sends samples to the Onserva platform.
//
// Every connection is outbound. The agent never listens on a port, so
// installing it opens no new way into the machine — which is what makes it
// safe to put on a client's server, behind their firewall, without asking them
// to change a thing.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	requestTimeout = 15 * time.Second
	maxErrorBody   = 512
)

type Client struct {
	url     string
	token   string
	version string
	http    *http.Client
}

func New(url, token, version string) *Client {
	return &Client{
		url:     url,
		token:   token,
		version: version,
		http: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				// One long-lived connection to one host. Keeping it alive
				// avoids a TLS handshake every 20 seconds.
				MaxIdleConns:        2,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
	}
}

// Response is what the platform tells us after accepting a sample.
type Response struct {
	OK                  bool `json:"ok"`
	Duplicate           bool `json:"duplicate"`
	NextIntervalSeconds int  `json:"next_interval_seconds"`

	// AuthorisedFixes is the pull model in one field: work the owner has
	// approved, handed back in the reply to a check-in the agent was making
	// anyway. It is why fix execution needs no new endpoint and no inbound
	// port — the machine is never contacted, it asks.
	AuthorisedFixes []AuthorisedFix `json:"authorised_fixes"`
}

// AuthorisedFix names an action, never a command.
//
// Kept as plain strings here so this package stays a transport: it carries what
// the platform said without opinions about it. Deciding whether the action is
// one this build implements, and whether the target is acceptable, belongs to
// the executor — and it is done again there, after this process has handed it
// on.
type AuthorisedFix struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Target string `json:"target"`
}

// SendError carries enough detail for the caller to decide whether keeping the
// sample is worth it.
type SendError struct {
	StatusCode int
	Retryable  bool
	RetryAfter time.Duration
	Message    string
}

func (e *SendError) Error() string {
	if e.StatusCode == 0 {
		return fmt.Sprintf("could not reach the platform: %s", e.Message)
	}
	return fmt.Sprintf("platform returned %d: %s", e.StatusCode, e.Message)
}

// Send posts a single sample.
//
// The returned error is always a *SendError, so the caller can distinguish
// "try again later" (network trouble, rate limit, platform outage) from
// "this sample will never be accepted" (malformed payload).
func (c *Client) Send(ctx context.Context, sample any) (Response, error) {
	body, err := json.Marshal(sample)
	if err != nil {
		// Our own bug, not the platform's. Never worth retrying.
		return Response{}, &SendError{Retryable: false, Message: "could not encode sample: " + err.Error()}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return Response{}, &SendError{Retryable: false, Message: err.Error()}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("User-Agent", "onserva-agent/"+c.version)

	response, err := c.http.Do(request)
	if err != nil {
		// DNS failure, refused connection, timeout — all transient by nature.
		return Response{}, &SendError{Retryable: true, Message: err.Error()}
	}
	defer func() {
		// Drain before closing so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxErrorBody))
		_ = response.Body.Close()
	}()

	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		var decoded Response
		if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&decoded); err != nil {
			// Accepted but unreadable reply: the sample is stored, which is
			// what matters. Carry on with our own interval.
			return Response{OK: true}, nil
		}
		return decoded, nil

	case response.StatusCode == http.StatusTooManyRequests:
		return Response{}, &SendError{
			StatusCode: response.StatusCode,
			Retryable:  true,
			RetryAfter: retryAfter(response),
			Message:    "reporting too frequently",
		}

	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		// Keep retrying: a server can be re-created with a new key, and going
		// permanently silent would be the worst possible failure mode for a
		// monitoring agent.
		return Response{}, &SendError{
			StatusCode: response.StatusCode,
			Retryable:  true,
			Message:    "the platform rejected this server's key — check SERVER_AGENT_TOKEN in /etc/onserva/agent.env",
		}

	case response.StatusCode >= 400 && response.StatusCode < 500:
		// Malformed or unacceptable payload. Retrying it forever would block
		// every later sample behind it.
		return Response{}, &SendError{
			StatusCode: response.StatusCode,
			Retryable:  false,
			Message:    readSnippet(response.Body),
		}

	default:
		return Response{}, &SendError{
			StatusCode: response.StatusCode,
			Retryable:  true,
			Message:    readSnippet(response.Body),
		}
	}
}

func retryAfter(response *http.Response) time.Duration {
	seconds, err := strconv.Atoi(response.Header.Get("Retry-After"))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func readSnippet(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, maxErrorBody))
	if err != nil || len(data) == 0 {
		return "no detail given"
	}
	return string(bytes.TrimSpace(data))
}
