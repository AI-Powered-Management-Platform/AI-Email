package store

import (
	"context"
	"fmt"
	"time"
)

type DomainRow struct {
	ID            int64
	Name          string
	Status        string
	Token         string
	DKIMSelector  string
	DKIMRecord    string
	VerifiedAt    *time.Time
	LastCheckedAt *time.Time
}

func (s *Store) ListDomains(ctx context.Context) ([]DomainRow, error) {
	const q = `
		SELECT d.id, d.name, d.status, d.verification_token,
		       coalesce(k.selector, ''), coalesce(k.public_record, ''),
		       d.verified_at, d.last_checked_at
		FROM domains d
		LEFT JOIN dkim_keys k ON k.domain_id = d.id AND k.active
		ORDER BY d.name`

	rows, err := s.Pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	defer rows.Close()

	var out []DomainRow
	for rows.Next() {
		var d DomainRow
		if err := rows.Scan(&d.ID, &d.Name, &d.Status, &d.Token, &d.DKIMSelector, &d.DKIMRecord,
			&d.VerifiedAt, &d.LastCheckedAt); err != nil {
			return nil, fmt.Errorf("reading domain: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type KeyRow struct {
	ID         int64
	Name       string
	Prefix     string
	Scopes     []string
	Quota      int
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
	LastUsedIP *string
}

// ListAPIKeys never selects secret_hash: the console has no use for it, and a
// value that is never loaded cannot be leaked by a template.
func (s *Store) ListAPIKeys(ctx context.Context) ([]KeyRow, error) {
	const q = `
		SELECT id, name, prefix, scopes, quota_per_hour, expires_at,
		       revoked_at, last_used_at, host(last_used_ip)
		FROM api_keys ORDER BY created_at DESC`

	rows, err := s.Pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing keys: %w", err)
	}
	defer rows.Close()

	var out []KeyRow
	for rows.Next() {
		var k KeyRow
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.Quota,
			&k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt, &k.LastUsedIP); err != nil {
			return nil, fmt.Errorf("reading key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

type MessageRow struct {
	ID         string
	Status     string
	From       string
	Recipients []string
	Subject    string
	Attempts   int
	LastError  *string
	SignedAt   *time.Time
	CreatedAt  time.Time
}

func (s *Store) ListMessages(ctx context.Context, status string, limit int) ([]MessageRow, error) {
	const q = `
		SELECT id, status, from_address, recipients, recipients_encrypted, subject,
		       attempts, last_error, signed_at, created_at
		FROM messages
		WHERE ($1 = '' OR status = $1)
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := s.Pool.Query(ctx, q, status, limit)
	if err != nil {
		return nil, fmt.Errorf("listing messages: %w", err)
	}
	defer rows.Close()

	var out []MessageRow
	for rows.Next() {
		var m MessageRow
		var clear []string
		var encrypted []byte
		if err := rows.Scan(&m.ID, &m.Status, &m.From, &clear, &encrypted, &m.Subject,
			&m.Attempts, &m.LastError, &m.SignedAt, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("reading message: %w", err)
		}
		if m.Recipients, err = s.unpackRecipients(encrypted, clear); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

type Counts struct {
	Queued    int
	Sent      int
	Failed    int
	Deferred  int
	LastHour  int
	Endpoints int
}

func (s *Store) DashboardCounts(ctx context.Context) (Counts, error) {
	const q = `
		SELECT
			count(*) FILTER (WHERE status = 'queued'),
			count(*) FILTER (WHERE status IN ('sent', 'delivered')),
			count(*) FILTER (WHERE status = 'failed'),
			count(*) FILTER (WHERE status = 'deferred'),
			count(*) FILTER (WHERE created_at > now() - interval '1 hour')
		FROM messages`

	var c Counts
	if err := s.Pool.QueryRow(ctx, q).Scan(&c.Queued, &c.Sent, &c.Failed, &c.Deferred, &c.LastHour); err != nil {
		return c, fmt.Errorf("counting messages: %w", err)
	}
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM webhook_endpoints WHERE active`).Scan(&c.Endpoints); err != nil {
		return c, fmt.Errorf("counting endpoints: %w", err)
	}
	return c, nil
}
