package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// SuppressionHash is how an address is looked up. Hashing means a deployment
// can eventually stop storing the address itself without changing any query.
func SuppressionHash(address string) []byte {
	sum := sha256.Sum256([]byte(normalizeAddress(address)))
	return sum[:]
}

func normalizeAddress(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

type Suppression struct {
	Address   string
	Reason    string
	Detail    string
	CreatedAt time.Time
}

// Suppress records an address we must not send to again. Repeating a
// suppression is not an error: the first reason is kept, because the earliest
// cause is the useful one.
func (s *Store) Suppress(ctx context.Context, address, reason, detail, messageID string) error {
	const q = `
		INSERT INTO suppressions (address, address_hash, reason, detail, message_id)
		VALUES ($1, $2, $3, $4, nullif($5, ''))
		ON CONFLICT (address_hash) DO NOTHING`

	if _, err := s.Pool.Exec(ctx, q, normalizeAddress(address), SuppressionHash(address), reason, detail, messageID); err != nil {
		return fmt.Errorf("suppressing address: %w", err)
	}
	return nil
}

// IsSuppressed reports whether an address is on the list.
func (s *Store) IsSuppressed(ctx context.Context, address string) (bool, error) {
	const q = `SELECT exists(SELECT 1 FROM suppressions WHERE address_hash = $1)`
	var found bool
	if err := s.Pool.QueryRow(ctx, q, SuppressionHash(address)).Scan(&found); err != nil {
		return false, fmt.Errorf("checking suppression: %w", err)
	}
	return found, nil
}

// FilterSuppressed splits recipients into those we may send to and those we
// may not. A message is not rejected outright when one recipient is
// suppressed: the others still deserve their mail.
func (s *Store) FilterSuppressed(ctx context.Context, addresses []string) (allowed, blocked []string, err error) {
	if len(addresses) == 0 {
		return nil, nil, nil
	}

	hashes := make([][]byte, 0, len(addresses))
	for _, a := range addresses {
		hashes = append(hashes, SuppressionHash(a))
	}

	const q = `SELECT address_hash FROM suppressions WHERE address_hash = ANY($1)`
	rows, err := s.Pool.Query(ctx, q, hashes)
	if err != nil {
		return nil, nil, fmt.Errorf("loading suppressions: %w", err)
	}
	defer rows.Close()

	found := make(map[string]bool)
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, nil, fmt.Errorf("reading suppression: %w", err)
		}
		found[string(h)] = true
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	for _, a := range addresses {
		if found[string(SuppressionHash(a))] {
			blocked = append(blocked, a)
			continue
		}
		allowed = append(allowed, a)
	}
	return allowed, blocked, nil
}

func (s *Store) Unsuppress(ctx context.Context, address string) error {
	const q = `DELETE FROM suppressions WHERE address_hash = $1`
	if _, err := s.Pool.Exec(ctx, q, SuppressionHash(address)); err != nil {
		return fmt.Errorf("removing suppression: %w", err)
	}
	return nil
}

func (s *Store) ListSuppressions(ctx context.Context, limit int) ([]Suppression, error) {
	const q = `SELECT address, reason, coalesce(detail, ''), created_at
	           FROM suppressions ORDER BY created_at DESC LIMIT $1`
	rows, err := s.Pool.Query(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("listing suppressions: %w", err)
	}
	defer rows.Close()

	var out []Suppression
	for rows.Next() {
		var sup Suppression
		if err := rows.Scan(&sup.Address, &sup.Reason, &sup.Detail, &sup.CreatedAt); err != nil {
			return nil, fmt.Errorf("reading suppression: %w", err)
		}
		out = append(out, sup)
	}
	return out, rows.Err()
}
