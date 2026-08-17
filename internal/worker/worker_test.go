package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/delivery"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

type fakeQueue struct {
	mu       sync.Mutex
	pending  []store.Claimed
	sentHour int

	sent     []string
	deferred map[string]time.Time
	failed   map[string]string
}

func newFakeQueue(msgs ...store.Claimed) *fakeQueue {
	return &fakeQueue{
		pending:  msgs,
		deferred: map[string]time.Time{},
		failed:   map[string]string{},
	}
}

func (q *fakeQueue) ClaimMessages(_ context.Context, limit int, _ time.Duration) ([]store.Claimed, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return nil, nil
	}
	if limit > len(q.pending) {
		limit = len(q.pending)
	}
	out := q.pending[:limit]
	q.pending = q.pending[limit:]
	return out, nil
}

func (q *fakeQueue) MarkSent(_ context.Context, id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sent = append(q.sent, id)
	return nil
}

func (q *fakeQueue) MarkDeferred(_ context.Context, id string, retryAt time.Time, _ string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.deferred[id] = retryAt
	return nil
}

func (q *fakeQueue) MarkFailed(_ context.Context, id, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.failed[id] = reason
	return nil
}

func (q *fakeQueue) SentInLastHour(context.Context) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.sentHour, nil
}

type fakeSender struct {
	mu       sync.Mutex
	response delivery.Response
	calls    int
}

func (s *fakeSender) Send(context.Context, delivery.Message) delivery.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.response
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func msg(id string, attempts int) store.Claimed {
	return store.Claimed{ID: id, FromAddress: "a@example.com", Recipients: []string{"b@example.org"}, Subject: "s", Attempts: attempts}
}

func TestSuccessfulDeliveryIsRecorded(t *testing.T) {
	q := newFakeQueue(msg("m1", 1))
	s := &fakeSender{response: delivery.Response{Result: delivery.Sent}}
	w := New(q, s, quietLogger(), 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(q.sent) != 1 || q.sent[0] != "m1" {
		t.Fatalf("expected m1 recorded as sent, got %v", q.sent)
	}
}

func TestTemporaryFailureDefersWithBackoff(t *testing.T) {
	q := newFakeQueue(msg("m1", 2))
	s := &fakeSender{response: delivery.Response{Result: delivery.Temporary, Reason: "engine unreachable"}}
	w := New(q, s, quietLogger(), 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	retryAt, ok := q.deferred["m1"]
	if !ok {
		t.Fatal("a temporary failure must defer, not fail")
	}
	if time.Until(retryAt) < time.Minute {
		t.Fatalf("retry should be delayed, got %v", time.Until(retryAt))
	}
	if len(q.failed) != 0 {
		t.Fatal("a temporary failure must not mark the message failed")
	}
}

func TestPermanentFailureDoesNotRetry(t *testing.T) {
	q := newFakeQueue(msg("m1", 1))
	s := &fakeSender{response: delivery.Response{Result: delivery.Permanent, Reason: "rejected"}}
	w := New(q, s, quietLogger(), 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if _, ok := q.failed["m1"]; !ok {
		t.Fatal("a permanent rejection must not be retried")
	}
	if len(q.deferred) != 0 {
		t.Fatal("a permanent rejection must not be deferred")
	}
}

func TestRetriesStopAtTheAttemptLimit(t *testing.T) {
	q := newFakeQueue(msg("m1", MaxAttempts))
	s := &fakeSender{response: delivery.Response{Result: delivery.Temporary, Reason: "still down"}}
	w := New(q, s, quietLogger(), 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if _, ok := q.failed["m1"]; !ok {
		t.Fatal("retrying forever damages reputation; the chain must end")
	}
}

func TestCeilingHoldsMessagesInsteadOfClaimingThem(t *testing.T) {
	q := newFakeQueue(msg("m1", 1))
	q.sentHour = 100
	s := &fakeSender{response: delivery.Response{Result: delivery.Sent}}
	w := New(q, s, quietLogger(), 100)

	processed, err := w.tick(context.Background())
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if processed != 0 || s.calls != 0 {
		t.Fatal("at the ceiling nothing may be dispatched")
	}
	if len(q.pending) != 1 {
		t.Fatal("held messages must stay in the queue, not be claimed and stalled")
	}
}

func TestCeilingOfZeroMeansNoCeilingCheck(t *testing.T) {
	q := newFakeQueue(msg("m1", 1))
	q.sentHour = 10_000
	s := &fakeSender{response: delivery.Response{Result: delivery.Sent}}
	w := New(q, s, quietLogger(), 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(q.sent) != 1 {
		t.Fatal("an unset ceiling must not block delivery")
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	first := Backoff(1)
	second := Backoff(2)
	if second <= first {
		t.Fatalf("backoff must grow: %v then %v", first, second)
	}
	if got := Backoff(100); got != 6*time.Hour {
		t.Fatalf("backoff must be capped, got %v", got)
	}
	if got := Backoff(0); got != time.Minute {
		t.Fatalf("first attempt should wait one minute, got %v", got)
	}
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	q := newFakeQueue()
	w := New(q, &fakeSender{response: delivery.Response{Result: delivery.Sent}}, quietLogger(), 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown should be clean, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop on cancellation")
	}
}
