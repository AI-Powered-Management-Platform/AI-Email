package webhook

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/netguard"
)

// maxResponseBytes bounds what we read back. The response is not used, so a
// slow endpoint dribbling megabytes is only ever an attack on us.
const maxResponseBytes = 8 << 10

type Outcome int

const (
	Delivered Outcome = iota
	Retry
	Drop
)

type Result struct {
	Outcome Outcome
	Reason  string
}

type Sender struct {
	client *http.Client
}

func NewSender(timeout time.Duration) *Sender {
	return &Sender{client: netguard.Client(timeout, 3)}
}

// Send posts one signed event. The destination is validated before the request
// and again on every redirect, and the connection is made to the address that
// was checked rather than to the name.
func (s *Sender) Send(ctx context.Context, url string, secret, payload []byte) Result {
	if _, err := netguard.ValidateURL(url); err != nil {
		// A destination that is not allowed will never become allowed by
		// retrying, and a tenant pointing at our own network is a
		// configuration error to surface, not to hammer.
		return Result{Drop, err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return Result{Drop, fmt.Sprintf("building request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aiemail-webhooks/1")
	Sign(req, payload, secret, time.Now())

	resp, err := s.client.Do(req)
	if err != nil {
		return Result{Retry, fmt.Sprintf("request failed: %v", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return Result{Delivered, ""}
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return Result{Retry, fmt.Sprintf("endpoint returned %d", resp.StatusCode)}
	case resp.StatusCode == http.StatusGone:
		return Result{Drop, "endpoint reported it is gone"}
	default:
		return Result{Retry, fmt.Sprintf("endpoint returned %d", resp.StatusCode)}
	}
}
