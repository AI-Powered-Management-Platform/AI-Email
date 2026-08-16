// Package keys issues and verifies API keys.
//
// An API key is a bearer credential: whoever holds it is the caller, with no
// further proof. Three properties follow, and each is enforced here rather
// than left to the caller — only a hash is stored, every key expires, and the
// clear-text secret exists exactly once, in the response that created it.
package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// LivePrefix identifies a key in logs, in the console, and to public secret
	// scanners, which is how a leaked key gets found before it is abused.
	LivePrefix = "aiem_live_"

	secretBytes = 32

	// DefaultLifetime applies when a caller does not choose one. Immortal
	// credentials are the failure mode this prevents.
	DefaultLifetime = 90 * 24 * time.Hour
	MaxLifetime     = 365 * 24 * time.Hour
)

var (
	ErrMalformed = errors.New("key is malformed")
	ErrExpired   = errors.New("key has expired")
	ErrRevoked   = errors.New("key has been revoked")
)

// encoding is unpadded and case-insensitive on decode, so a key survives being
// copied through systems that change case or trim padding.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Generated is returned once, at creation. The Secret is never stored and
// cannot be recovered.
type Generated struct {
	Secret string
	Hash   []byte
	Prefix string
}

func Generate() (Generated, error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return Generated{}, fmt.Errorf("generating key material: %w", err)
	}

	secret := LivePrefix + strings.ToLower(encoding.EncodeToString(raw))
	return Generated{
		Secret: secret,
		Hash:   Hash(secret),
		Prefix: Display(secret),
	}, nil
}

// Hash is what the database stores. The secret carries 256 bits of entropy, so
// a fast hash is appropriate: there is nothing to brute force, and lookups
// must stay indexable.
func Hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Equal compares hashes in constant time.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Display returns the fragment safe to show after creation. It identifies a
// key without being usable as one.
func Display(secret string) string {
	body := strings.TrimPrefix(secret, LivePrefix)
	if len(body) < 6 {
		return LivePrefix + "…"
	}
	return LivePrefix + body[:6] + "…"
}

// Parse validates the shape of a presented key before any database work, so a
// malformed credential costs no query.
func Parse(secret string) error {
	if !strings.HasPrefix(secret, LivePrefix) {
		return ErrMalformed
	}
	body := strings.TrimPrefix(secret, LivePrefix)
	decoded, err := encoding.DecodeString(strings.ToUpper(body))
	if err != nil {
		return ErrMalformed
	}
	if len(decoded) != secretBytes {
		return ErrMalformed
	}
	return nil
}

// Lifetime clamps a requested lifetime into the permitted range.
func Lifetime(requested time.Duration) time.Duration {
	switch {
	case requested <= 0:
		return DefaultLifetime
	case requested > MaxLifetime:
		return MaxLifetime
	default:
		return requested
	}
}
