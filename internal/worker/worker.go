// Package worker drains the queue.
//
// It is deliberately conservative: it stops when the deployment ceiling is
// reached, it backs off rather than hammering a struggling destination, and it
// prefers leaving a message queued over risking a duplicate send.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/delivery"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/dkim"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/mail"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

const (
	batchSize    = 10
	lockDuration = 5 * time.Minute
	idleInterval = 5 * time.Second

	// MaxAttempts ends the retry chain. A message that has failed this many
	// times is not going to succeed, and continuing to try damages reputation.
	MaxAttempts = 8
)

type Queue interface {
	ClaimMessages(ctx context.Context, limit int, lockFor time.Duration) ([]store.Claimed, error)
	MarkSent(ctx context.Context, id string) error
	MarkDeferred(ctx context.Context, id string, retryAt time.Time, reason string) error
	MarkFailed(ctx context.Context, id, reason string) error
	SentInLastHour(ctx context.Context) (int, error)
}

type Sender interface {
	Send(ctx context.Context, msg delivery.Message) delivery.Response
}

// KeyStore supplies wrapped signing material. It never returns a usable key.
type KeyStore interface {
	SigningKeyForMessage(ctx context.Context, messageID string) (*store.SigningKey, error)
	MarkSigned(ctx context.Context, messageID string) error
}

type MessageSigner interface {
	Sign(ctx context.Context, key dkim.Key, message []byte) ([]byte, error)
}

type Worker struct {
	queue      Queue
	sender     Sender
	keys       KeyStore
	signer     MessageSigner
	log        *slog.Logger
	maxPerHour int
}

func New(queue Queue, sender Sender, keys KeyStore, signer MessageSigner, log *slog.Logger, maxPerHour int) *Worker {
	return &Worker{queue: queue, sender: sender, keys: keys, signer: signer, log: log, maxPerHour: maxPerHour}
}

// Run drains the queue until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("worker started", "batch", batchSize, "ceiling_per_hour", w.maxPerHour)

	for {
		processed, err := w.tick(ctx)
		if err != nil {
			if ctx.Err() != nil {
				w.log.Info("worker stopped")
				return nil
			}
			w.log.Error("worker tick failed", "error", err)
		}

		// Only pause when there was nothing to do, so a backlog drains at full
		// speed while an idle queue costs almost nothing.
		wait := time.Duration(0)
		if processed == 0 || err != nil {
			wait = idleInterval
		}
		select {
		case <-ctx.Done():
			w.log.Info("worker stopped")
			return nil
		case <-time.After(wait):
		}
	}
}

func (w *Worker) tick(ctx context.Context) (int, error) {
	// The ceiling is checked before claiming, so hitting it leaves messages
	// untouched in the queue rather than claimed and stalled.
	if w.maxPerHour > 0 {
		sent, err := w.queue.SentInLastHour(ctx)
		if err != nil {
			return 0, err
		}
		if sent >= w.maxPerHour {
			w.log.Warn("hourly ceiling reached, holding delivery", "sent", sent, "ceiling", w.maxPerHour)
			return 0, nil
		}
	}

	claimed, err := w.queue.ClaimMessages(ctx, batchSize, lockDuration)
	if err != nil {
		return 0, err
	}

	for _, msg := range claimed {
		w.deliver(ctx, msg)
	}
	return len(claimed), nil
}

func (w *Worker) deliver(ctx context.Context, msg store.Claimed) {
	raw, err := w.sign(ctx, msg)
	if err != nil {
		// Unsigned mail is refused by mailbox providers and damages the domain
		// that sent it, so a signing failure stops the message rather than
		// letting it go out bare.
		w.fail(ctx, msg, "could not sign message: "+err.Error())
		return
	}

	resp := w.sender.Send(ctx, delivery.Message{
		ID:      msg.ID,
		From:    msg.FromAddress,
		To:      msg.Recipients,
		Subject: msg.Subject,
		HTML:    msg.BodyHTML,
		Text:    msg.BodyText,
		Headers: decodeHeaders(msg.Headers),
		Raw:     raw,
	})

	switch resp.Result {
	case delivery.Sent:
		if err := w.queue.MarkSent(ctx, msg.ID); err != nil {
			// The message was handed over but the record failed. The lock will
			// expire and it will be retried, which is why the engine dedupes on
			// the message id.
			w.log.Error("delivered but could not record", "message_id", msg.ID, "error", err)
			return
		}
		w.log.Info("delivered", "message_id", msg.ID, "attempts", msg.Attempts)

	case delivery.Temporary:
		if msg.Attempts >= MaxAttempts {
			w.fail(ctx, msg, "gave up after repeated temporary failures: "+resp.Reason)
			return
		}
		retryAt := time.Now().Add(Backoff(msg.Attempts))
		if err := w.queue.MarkDeferred(ctx, msg.ID, retryAt, resp.Reason); err != nil {
			w.log.Error("could not defer message", "message_id", msg.ID, "error", err)
			return
		}
		w.log.Info("deferred", "message_id", msg.ID, "attempts", msg.Attempts, "retry_at", retryAt)

	case delivery.Permanent:
		w.fail(ctx, msg, resp.Reason)
	}
}

// sign builds the RFC 5322 message and signs it. The key is unwrapped inside
// the signer and discarded with the call.
func (w *Worker) sign(ctx context.Context, msg store.Claimed) ([]byte, error) {
	if w.signer == nil || w.keys == nil {
		return nil, errors.New("no signing key is configured")
	}

	key, err := w.keys.SigningKeyForMessage(ctx, msg.ID)
	if err != nil {
		return nil, fmt.Errorf("no active signing key for this domain: %w", err)
	}

	raw, err := mail.Build(mail.Envelope{
		MessageID: msg.ID + "@" + key.Domain,
		From:      msg.FromAddress,
		To:        msg.Recipients,
		Subject:   msg.Subject,
		HTML:      msg.BodyHTML,
		Text:      msg.BodyText,
		Extra:     decodeHeaders(msg.Headers),
	})
	if err != nil {
		return nil, err
	}

	signed, err := w.signer.Sign(ctx, dkim.Key{
		Domain:    key.Domain,
		Selector:  key.Selector,
		Algorithm: key.Algorithm,
		Wrapped:   key.Wrapped,
	}, raw)
	if err != nil {
		return nil, err
	}

	if err := w.keys.MarkSigned(ctx, msg.ID); err != nil {
		w.log.Warn("could not record signing time", "message_id", msg.ID, "error", err)
	}
	return signed, nil
}

func (w *Worker) fail(ctx context.Context, msg store.Claimed, reason string) {
	if err := w.queue.MarkFailed(ctx, msg.ID, reason); err != nil {
		w.log.Error("could not fail message", "message_id", msg.ID, "error", err)
		return
	}
	w.log.Warn("delivery failed", "message_id", msg.ID, "attempts", msg.Attempts, "reason", reason)
}

// Backoff grows exponentially and is capped. Retrying a struggling destination
// faster than it recovers is read as an attack, not as diligence.
func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	const base = time.Minute
	const max = 6 * time.Hour

	shift := math.Min(float64(attempt-1), 20)
	delay := time.Duration(float64(base) * math.Pow(2, shift))
	if delay > max || delay <= 0 {
		return max
	}
	return delay
}

func decodeHeaders(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
