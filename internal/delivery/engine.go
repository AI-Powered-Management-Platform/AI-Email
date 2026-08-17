// Package delivery hands accepted messages to the sending engine.
//
// The engine speaks SMTP to the internet; this service never does. That split
// is deliberate: the queue logic that decides when and how fast to retry is
// where deliverability is won or lost, and it belongs in software built for it.
package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Result classifies what the engine said. The distinction drives whether a
// message is retried, and retrying something permanent is how a sender teaches
// mailbox providers that it does not listen.
type Result int

const (
	Sent Result = iota
	Temporary
	Permanent
)

type Response struct {
	Result Result
	Reason string
}

type Message struct {
	ID      string            `json:"id"`
	From    string            `json:"from"`
	To      []string          `json:"to"`
	Subject string            `json:"subject"`
	HTML    string            `json:"html,omitempty"`
	Text    string            `json:"text,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type Engine struct {
	baseURL string
	client  *http.Client
}

func NewEngine(baseURL string) *Engine {
	return &Engine{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
				MaxIdleConnsPerHost: 4,
			},
		},
	}
}

// Send hands one message over. The message id travels with it so the engine
// can discard a duplicate: delivery is at-least-once, because a worker that
// dies after handing off but before recording success will try again.
func (e *Engine) Send(ctx context.Context, msg Message) Response {
	body, err := json.Marshal(msg)
	if err != nil {
		return Response{Permanent, fmt.Sprintf("encoding message: %v", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/api/inject/v1", bytes.NewReader(body))
	if err != nil {
		return Response{Permanent, fmt.Sprintf("building request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", msg.ID)

	resp, err := e.client.Do(req)
	if err != nil {
		// The engine being unreachable says nothing about the message, so this
		// is always temporary.
		return Response{Temporary, fmt.Sprintf("engine unreachable: %v", err)}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return Response{Sent, ""}
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return Response{Temporary, fmt.Sprintf("engine returned %d", resp.StatusCode)}
	default:
		return Response{Permanent, fmt.Sprintf("engine rejected the message with %d", resp.StatusCode)}
	}
}

var ErrNotConfigured = errors.New("no sending engine is configured")
