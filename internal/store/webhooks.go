package store

import (
	"context"
	"fmt"
	"time"
)

type Endpoint struct {
	ID     int64
	URL    string
	Secret []byte
}

func (s *Store) CreateEndpoint(ctx context.Context, url string, secret []byte) (*Endpoint, error) {
	const q = `INSERT INTO webhook_endpoints (url, secret) VALUES ($1, $2) RETURNING id, url, secret`
	var e Endpoint
	if err := s.Pool.QueryRow(ctx, q, url, secret).Scan(&e.ID, &e.URL, &e.Secret); err != nil {
		return nil, fmt.Errorf("creating endpoint: %w", err)
	}
	return &e, nil
}

func (s *Store) ActiveEndpoints(ctx context.Context) ([]Endpoint, error) {
	const q = `SELECT id, url, secret FROM webhook_endpoints WHERE active ORDER BY id`
	rows, err := s.Pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("loading endpoints: %w", err)
	}
	defer rows.Close()

	var out []Endpoint
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.ID, &e.URL, &e.Secret); err != nil {
			return nil, fmt.Errorf("reading endpoint: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EnqueueDelivery fans one event out to every active endpoint. The unique
// constraint on (endpoint, event) makes this safe to call twice: a worker that
// crashes after recording an event but before queueing its webhooks can repeat
// the call without producing duplicate deliveries.
func (s *Store) EnqueueDelivery(ctx context.Context, eventID, messageID string, payload []byte) error {
	const q = `
		INSERT INTO webhook_deliveries (endpoint_id, event_id, message_id, payload)
		SELECT id, $1, $2, $3 FROM webhook_endpoints WHERE active
		ON CONFLICT (endpoint_id, event_id) DO NOTHING`
	if _, err := s.Pool.Exec(ctx, q, eventID, messageID, payload); err != nil {
		return fmt.Errorf("queueing webhook delivery: %w", err)
	}
	return nil
}

type PendingDelivery struct {
	ID       int64
	URL      string
	Secret   []byte
	Payload  []byte
	Attempts int
}

func (s *Store) ClaimDeliveries(ctx context.Context, limit int, lockFor time.Duration) ([]PendingDelivery, error) {
	const q = `
		UPDATE webhook_deliveries d SET
			status       = 'delivering',
			attempts     = d.attempts + 1,
			locked_until = now() + $2::interval
		FROM webhook_endpoints e
		WHERE e.id = d.endpoint_id AND d.id IN (
			SELECT id FROM webhook_deliveries
			WHERE status = 'pending'
			  AND next_attempt <= now()
			  AND (locked_until IS NULL OR locked_until < now())
			ORDER BY next_attempt
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING d.id, e.url, e.secret, d.payload, d.attempts`

	rows, err := s.Pool.Query(ctx, q, limit, lockFor.String())
	if err != nil {
		return nil, fmt.Errorf("claiming deliveries: %w", err)
	}
	defer rows.Close()

	var out []PendingDelivery
	for rows.Next() {
		var d PendingDelivery
		if err := rows.Scan(&d.ID, &d.URL, &d.Secret, &d.Payload, &d.Attempts); err != nil {
			return nil, fmt.Errorf("reading delivery: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) MarkDeliverySucceeded(ctx context.Context, id int64) error {
	const q = `UPDATE webhook_deliveries SET status='delivered', locked_until=NULL WHERE id=$1`
	if _, err := s.Pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("recording delivery: %w", err)
	}
	return nil
}

func (s *Store) RescheduleDelivery(ctx context.Context, id int64, at time.Time, reason string) error {
	const q = `
		UPDATE webhook_deliveries
		SET status='pending', next_attempt=$2, locked_until=NULL, last_error=$3
		WHERE id=$1`
	if _, err := s.Pool.Exec(ctx, q, id, at, truncate(reason, 500)); err != nil {
		return fmt.Errorf("rescheduling delivery: %w", err)
	}
	return nil
}

func (s *Store) MarkDeliveryFailed(ctx context.Context, id int64, reason string) error {
	const q = `UPDATE webhook_deliveries SET status='failed', locked_until=NULL, last_error=$2 WHERE id=$1`
	if _, err := s.Pool.Exec(ctx, q, id, truncate(reason, 500)); err != nil {
		return fmt.Errorf("failing delivery: %w", err)
	}
	return nil
}

// DomainsDueForRecheck returns verified domains whose proof has not been
// confirmed recently. Trust granted once must be re-earned.
func (s *Store) DomainsDueForRecheck(ctx context.Context, olderThan time.Duration, limit int) ([]DomainProof, error) {
	const q = `
		SELECT id, name, verification_token, status
		FROM domains
		WHERE status IN ('verified', 'pending')
		  AND (last_checked_at IS NULL OR last_checked_at < now() - $1::interval)
		ORDER BY last_checked_at NULLS FIRST
		LIMIT $2`

	rows, err := s.Pool.Query(ctx, q, olderThan.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("loading domains for recheck: %w", err)
	}
	defer rows.Close()

	var out []DomainProof
	for rows.Next() {
		var d DomainProof
		if err := rows.Scan(&d.ID, &d.Name, &d.Token, &d.Status); err != nil {
			return nil, fmt.Errorf("reading domain: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type DomainProof struct {
	ID     int64
	Name   string
	Token  string
	Status string
}

func (s *Store) MarkDomainVerified(ctx context.Context, id int64) error {
	const q = `
		UPDATE domains
		SET status='verified', verified_at=coalesce(verified_at, now()), last_checked_at=now()
		WHERE id=$1`
	if _, err := s.Pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("marking domain verified: %w", err)
	}
	return nil
}

// SuspendDomain stops sending for a domain whose proof has gone. Called only
// when the record is genuinely absent, never on a resolver failure.
func (s *Store) SuspendDomain(ctx context.Context, id int64) error {
	const q = `UPDATE domains SET status='suspended', last_checked_at=now() WHERE id=$1`
	if _, err := s.Pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("suspending domain: %w", err)
	}
	return nil
}

// TouchDomainCheck records an attempt without changing trust, used when the
// lookup itself failed.
func (s *Store) TouchDomainCheck(ctx context.Context, id int64) error {
	const q = `UPDATE domains SET last_checked_at=now() WHERE id=$1`
	if _, err := s.Pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("recording domain check: %w", err)
	}
	return nil
}
