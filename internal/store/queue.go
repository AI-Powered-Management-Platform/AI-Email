package store

import (
	"context"
	"fmt"
	"time"
)

// Claimed is a message a worker has taken responsibility for.
type Claimed struct {
	ID          string
	FromAddress string
	Recipients  []string
	Subject     string
	BodyHTML    string
	BodyText    string
	Headers     []byte
	Attempts    int
}

// ClaimMessages takes up to limit due messages and holds them for lockFor.
//
// SKIP LOCKED lets several workers share the queue without blocking each
// other. The lock is a timestamp rather than a session lock on purpose: if a
// worker dies mid-delivery the lock simply expires and the message is retried,
// which is what makes the queue survive a crash. Delivery is therefore
// at-least-once, so the engine must dedupe on the message id.
func (s *Store) ClaimMessages(ctx context.Context, limit int, lockFor time.Duration) ([]Claimed, error) {
	const q = `
		UPDATE messages SET
			status       = 'sending',
			attempts     = attempts + 1,
			locked_until = now() + $2::interval,
			updated_at   = now()
		WHERE id IN (
			SELECT id FROM messages
			WHERE status IN ('queued', 'deferred')
			  AND (scheduled_at IS NULL OR scheduled_at <= now())
			  AND (locked_until IS NULL OR locked_until < now())
			ORDER BY created_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, from_address, recipients, subject, body_html, body_text, headers, attempts`

	rows, err := s.Pool.Query(ctx, q, limit, lockFor.String())
	if err != nil {
		return nil, fmt.Errorf("claiming messages: %w", err)
	}
	defer rows.Close()

	var out []Claimed
	for rows.Next() {
		var c Claimed
		if err := rows.Scan(&c.ID, &c.FromAddress, &c.Recipients, &c.Subject,
			&c.BodyHTML, &c.BodyText, &c.Headers, &c.Attempts); err != nil {
			return nil, fmt.Errorf("reading claimed message: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkSent records a successful handoff to the sending engine.
func (s *Store) MarkSent(ctx context.Context, id string) error {
	return s.transition(ctx, id, "sent", "email.sent", nil, nil)
}

// MarkDeferred schedules a retry. The message stays claimable, so a permanent
// worker outage cannot strand it.
func (s *Store) MarkDeferred(ctx context.Context, id string, retryAt time.Time, reason string) error {
	const q = `
		UPDATE messages SET
			status       = 'deferred',
			scheduled_at = $2,
			locked_until = NULL,
			last_error   = $3,
			updated_at   = now()
		WHERE id = $1`
	if _, err := s.Pool.Exec(ctx, q, id, retryAt, truncate(reason, 500)); err != nil {
		return fmt.Errorf("deferring message: %w", err)
	}
	return s.RecordEvent(ctx, id, "email.deferred", reason)
}

// MarkFailed ends delivery attempts.
func (s *Store) MarkFailed(ctx context.Context, id, reason string) error {
	return s.transition(ctx, id, "failed", "email.failed", &reason, nil)
}

func (s *Store) transition(ctx context.Context, id, status, event string, reason *string, _ *time.Time) error {
	const q = `
		UPDATE messages SET
			status       = $2,
			locked_until = NULL,
			last_error   = $3,
			updated_at   = now()
		WHERE id = $1`
	var errText *string
	if reason != nil {
		t := truncate(*reason, 500)
		errText = &t
	}
	if _, err := s.Pool.Exec(ctx, q, id, status, errText); err != nil {
		return fmt.Errorf("updating message status: %w", err)
	}
	detail := ""
	if reason != nil {
		detail = *reason
	}
	return s.RecordEvent(ctx, id, event, detail)
}

// RecordEvent appends to the message history. Events are the audit trail, so
// they are only ever inserted.
func (s *Store) RecordEvent(ctx context.Context, messageID, eventType, detail string) error {
	const q = `INSERT INTO message_events (message_id, type, detail) VALUES ($1, $2, $3)`
	payload := []byte(`{}`)
	if detail != "" {
		payload = mustJSONString(truncate(detail, 500))
	}
	if _, err := s.Pool.Exec(ctx, q, messageID, eventType, payload); err != nil {
		return fmt.Errorf("recording event: %w", err)
	}
	return nil
}

// SentInLastHour counts deployment-wide dispatches. This backs the per-hour
// ceiling, which is the backstop for every other defect: a bug that would
// flood cannot flood if this holds.
func (s *Store) SentInLastHour(ctx context.Context) (int, error) {
	const q = `
		SELECT count(*) FROM message_events
		WHERE type = 'email.sent' AND occurred_at > now() - interval '1 hour'`
	var n int
	if err := s.Pool.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting recent dispatches: %w", err)
	}
	return n, nil
}

type Event struct {
	Type       string
	Detail     string
	OccurredAt time.Time
}

func (s *Store) EventsForMessage(ctx context.Context, messageID string) ([]Event, error) {
	const q = `
		SELECT type, coalesce(detail->>'reason', ''), occurred_at
		FROM message_events WHERE message_id = $1 ORDER BY occurred_at, id`
	rows, err := s.Pool.Query(ctx, q, messageID)
	if err != nil {
		return nil, fmt.Errorf("loading events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Type, &e.Detail, &e.OccurredAt); err != nil {
			return nil, fmt.Errorf("reading event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func mustJSONString(reason string) []byte {
	out := make([]byte, 0, len(reason)+16)
	out = append(out, `{"reason":`...)
	out = appendJSONString(out, reason)
	out = append(out, '}')
	return out
}

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for _, r := range s {
		switch r {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if r < 0x20 {
				dst = append(dst, ' ')
				continue
			}
			dst = append(dst, string(r)...)
		}
	}
	return append(dst, '"')
}
