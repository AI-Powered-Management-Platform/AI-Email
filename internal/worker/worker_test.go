package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/delivery"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/dkim"
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

// fakeKeys returns wrapped material; the fake signer stands in for the real
// one so these tests stay about queue behaviour, not cryptography.
type fakeKeys struct {
	err    error
	signed []string
	mu     sync.Mutex
}

func (f *fakeKeys) SigningKeyForMessage(context.Context, string) (*store.SigningKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &store.SigningKey{Domain: "example.com", Selector: "s1", Algorithm: "ed25519", Wrapped: []byte("wrapped")}, nil
}

func (f *fakeKeys) MarkSigned(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signed = append(f.signed, id)
	return nil
}

type fakeSigner struct{ err error }

func (f fakeSigner) Sign(_ context.Context, _ dkim.Key, message []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte("DKIM-Signature: stub\r\n"), message...), nil
}

// newWorker wires a worker with working signing, so each test states only what
// it cares about.
func newWorker(q Queue, s Sender, maxPerHour int) *Worker {
	return New(q, s, &fakeKeys{}, fakeSigner{}, quietLogger(), maxPerHour)
}

func msg(id string, attempts int) store.Claimed {
	return store.Claimed{ID: id, FromAddress: "a@example.com", Recipients: []string{"b@example.org"}, Subject: "s", Attempts: attempts}
}

func TestSuccessfulDeliveryIsRecorded(t *testing.T) {
	q := newFakeQueue(msg("m1", 1))
	s := &fakeSender{response: delivery.Response{Result: delivery.Sent}}
	w := newWorker(q, s, 0)

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
	w := newWorker(q, s, 0)

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
	w := newWorker(q, s, 0)

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
	w := newWorker(q, s, 0)

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
	w := newWorker(q, s, 100)

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
	w := newWorker(q, s, 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(q.sent) != 1 {
		t.Fatal("an unset ceiling must not block delivery")
	}
}

// Unsigned mail is refused by mailbox providers and damages the sending
// domain, so a signing failure must stop the message rather than let it go out
// bare.
func TestMessageThatCannotBeSignedIsNeverSent(t *testing.T) {
	q := newFakeQueue(msg("m1", 1))
	s := &fakeSender{response: delivery.Response{Result: delivery.Sent}}
	w := New(q, s, &fakeKeys{err: errors.New("no key for domain")}, fakeSigner{}, quietLogger(), 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if s.calls != 0 {
		t.Fatal("a message that could not be signed reached the sending engine")
	}
	if _, ok := q.failed["m1"]; !ok {
		t.Fatal("an unsignable message must be failed, not silently dropped")
	}
}

func TestSigningFailureAlsoStopsDelivery(t *testing.T) {
	q := newFakeQueue(msg("m1", 1))
	s := &fakeSender{response: delivery.Response{Result: delivery.Sent}}
	w := New(q, s, &fakeKeys{}, fakeSigner{err: errors.New("key unwrap failed")}, quietLogger(), 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if s.calls != 0 {
		t.Fatal("a signing failure must stop the message before dispatch")
	}
}

func TestSignedMessageIsWhatGetsHandedToTheEngine(t *testing.T) {
	q := newFakeQueue(msg("m1", 1))
	var captured delivery.Message
	s := &capturingSender{response: delivery.Response{Result: delivery.Sent}, capture: &captured}
	w := New(q, s, &fakeKeys{}, fakeSigner{}, quietLogger(), 0)

	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(captured.Raw) == 0 {
		t.Fatal("the engine must receive the signed bytes, not just the fields")
	}
	if !strings.HasPrefix(string(captured.Raw), "DKIM-Signature:") {
		t.Fatalf("the handed-off message is not signed: %q", string(captured.Raw[:min(40, len(captured.Raw))]))
	}
}

type capturingSender struct {
	response delivery.Response
	capture  *delivery.Message
}

func (s *capturingSender) Send(_ context.Context, msg delivery.Message) delivery.Response {
	*s.capture = msg
	return s.response
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
	w := newWorker(q, &fakeSender{response: delivery.Response{Result: delivery.Sent}}, 0)

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
