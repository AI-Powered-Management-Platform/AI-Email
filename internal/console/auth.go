// Package console serves the operator interface from the same binary as the
// API, so a self-hosted deployment runs one process and installs no runtime.
//
// The console holds key management, which makes a stolen session equivalent to
// a stolen key. Sessions are therefore short, bound to a cookie that scripts
// cannot read, and every state change carries a token tied to the session.
package console

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	sessionCookie = "aiemail_console"

	// SessionTTL is short because this session can create sending credentials.
	SessionTTL = 2 * time.Hour

	// loginDelay makes online guessing expensive without needing a lockout
	// table for a single-operator console.
	loginDelay = 500 * time.Millisecond
)

// PasswordHash is the stored form of the console password: argon2id with a
// random salt, encoded so it can live in an environment variable.
type PasswordHash struct {
	Salt []byte
	Hash []byte
}

func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", fmt.Errorf("console password must be at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return "argon2id$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash), nil
}

func ParsePasswordHash(encoded string) (*PasswordHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return nil, fmt.Errorf("password hash is not in the expected argon2id format")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("password hash salt is not valid base64")
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("password hash is not valid base64")
	}
	return &PasswordHash{Salt: salt, Hash: hash}, nil
}

// Verify compares in constant time.
func (p *PasswordHash) Verify(password string) bool {
	candidate := argon2.IDKey([]byte(password), p.Salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(candidate, p.Hash) == 1
}

type session struct {
	csrf    string
	expires time.Time
}

type sessions struct {
	mu   sync.Mutex
	live map[string]session
}

func newSessions() *sessions {
	return &sessions{live: map[string]session{}}
}

func (s *sessions) create() (id, csrf string, err error) {
	id, err = randomToken()
	if err != nil {
		return "", "", err
	}
	csrf, err = randomToken()
	if err != nil {
		return "", "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	s.live[id] = session{csrf: csrf, expires: time.Now().Add(SessionTTL)}
	return id, csrf, nil
}

func (s *sessions) get(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.live[id]
	if !ok || time.Now().After(sess.expires) {
		delete(s.live, id)
		return session{}, false
	}
	return sess, true
}

func (s *sessions) destroy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.live, id)
}

func (s *sessions) prune() {
	now := time.Now()
	for id, sess := range s.live {
		if now.After(sess.expires) {
			delete(s.live, id)
		}
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setSessionCookie marks the cookie HttpOnly so a script cannot read it, and
// SameSite=Strict so another site cannot cause an authenticated request.
func setSessionCookie(w http.ResponseWriter, id string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/console",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(SessionTTL),
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/console",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// validCSRF compares the submitted token with the session's in constant time.
func validCSRF(expected, submitted string) bool {
	return hmac.Equal([]byte(expected), []byte(submitted))
}

var _ = sha256.New
