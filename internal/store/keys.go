package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrNotFound = errors.New("not found")

type APIKey struct {
	ID           int64
	Name         string
	Prefix       string
	Scopes       []string
	QuotaPerHour int
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	LastUsedAt   *time.Time
}

func (k *APIKey) HasScope(want string) bool {
	for _, s := range k.Scopes {
		if s == want {
			return true
		}
	}
	return false
}

func (k *APIKey) Revoked() bool { return k.RevokedAt != nil }

func (k *APIKey) Expired(now time.Time) bool { return !now.Before(k.ExpiresAt) }

type NewAPIKey struct {
	Name         string
	Prefix       string
	SecretHash   []byte
	Scopes       []string
	QuotaPerHour int
	ExpiresAt    time.Time
}

func (s *Store) CreateAPIKey(ctx context.Context, in NewAPIKey) (*APIKey, error) {
	const q = `
		INSERT INTO api_keys (name, prefix, secret_hash, scopes, quota_per_hour, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, prefix, scopes, quota_per_hour, expires_at, revoked_at, last_used_at`

	var k APIKey
	err := s.Pool.QueryRow(ctx, q, in.Name, in.Prefix, in.SecretHash, in.Scopes, in.QuotaPerHour, in.ExpiresAt).
		Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.QuotaPerHour, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt)
	if err != nil {
		return nil, fmt.Errorf("creating api key: %w", err)
	}
	return &k, nil
}

// APIKeyByHash looks the key up by hash. The clear-text secret never reaches
// the database, so a query log cannot leak a working credential.
func (s *Store) APIKeyByHash(ctx context.Context, hash []byte) (*APIKey, error) {
	const q = `
		SELECT id, name, prefix, scopes, quota_per_hour, expires_at, revoked_at, last_used_at
		FROM api_keys WHERE secret_hash = $1`

	var k APIKey
	err := s.Pool.QueryRow(ctx, q, hash).
		Scan(&k.ID, &k.Name, &k.Prefix, &k.Scopes, &k.QuotaPerHour, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading api key: %w", err)
	}
	return &k, nil
}

// TouchAPIKey records where and when a key was last used, which is how an
// owner notices a stranger holding their credential.
func (s *Store) TouchAPIKey(ctx context.Context, id int64, addr netip.Addr) error {
	var ip *string
	if addr.IsValid() {
		s := addr.String()
		ip = &s
	}
	const q = `UPDATE api_keys SET last_used_at = now(), last_used_ip = $2 WHERE id = $1`
	if _, err := s.Pool.Exec(ctx, q, id, ip); err != nil {
		return fmt.Errorf("recording key use: %w", err)
	}
	return nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, id int64) error {
	const q = `UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`
	tag, err := s.Pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("revoking key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SendsInLastHour counts messages accepted for a key, enforcing its quota.
func (s *Store) SendsInLastHour(ctx context.Context, keyID int64) (int, error) {
	const q = `SELECT count(*) FROM messages WHERE api_key_id = $1 AND created_at > now() - interval '1 hour'`
	var n int
	if err := s.Pool.QueryRow(ctx, q, keyID).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting recent sends: %w", err)
	}
	return n, nil
}
