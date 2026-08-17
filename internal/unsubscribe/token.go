// Package unsubscribe issues and checks one-click unsubscribe tokens.
//
// Two failure modes shape this design. A guessable link lets an attacker
// unsubscribe a tenant's entire list. And corporate mail scanners fetch every
// link in a message, so a GET that changes state unsubscribes readers who
// never clicked anything.
package unsubscribe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Lifetime bounds how long a link stays usable. Long enough that a message
// read weeks later still works, short enough that an old capture expires.
const Lifetime = 90 * 24 * time.Hour

var (
	ErrMalformed    = errors.New("unsubscribe link is malformed")
	ErrExpired      = errors.New("unsubscribe link has expired")
	ErrBadSignature = errors.New("unsubscribe link is not valid")
)

// DeriveSecret produces the signing secret from the deployment master key.
//
// A separate configuration value would be one more secret for an operator to
// generate, store, and eventually leak. The label keeps this key distinct from
// any other use of the master key.
func DeriveSecret(masterKey []byte) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("aiemail/unsubscribe/v1"))
	return mac.Sum(nil)
}

type Token struct {
	MessageID string
	Address   string
	ExpiresAt time.Time
}

// Sign returns a token bound to one recipient of one message. Binding both
// means a link cannot be reused to unsubscribe somebody else.
func Sign(secret []byte, messageID, address string, now time.Time) string {
	expiry := now.Add(Lifetime).Unix()
	payload := payloadOf(messageID, address, expiry)
	sig := mac(secret, payload)

	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}

// Verify checks a token and returns what it authorises.
func Verify(secret []byte, token string, now time.Time) (*Token, error) {
	encodedPayload, encodedSig, found := strings.Cut(token, ".")
	if !found {
		return nil, ErrMalformed
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil {
		return nil, ErrMalformed
	}

	// Compared before parsing, so a forged payload is never interpreted.
	if !hmac.Equal(mac(secret, string(payload)), sig) {
		return nil, ErrBadSignature
	}

	parts := strings.Split(string(payload), "\x00")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	expiry, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, ErrMalformed
	}
	if now.After(time.Unix(expiry, 0)) {
		return nil, ErrExpired
	}

	return &Token{MessageID: parts[0], Address: parts[1], ExpiresAt: time.Unix(expiry, 0)}, nil
}

// Link builds the absolute URL placed in the message headers.
func Link(baseURL, token string) string {
	return strings.TrimSuffix(baseURL, "/") + "/u/" + token
}

// Headers returns the RFC 8058 header pair.
//
// List-Unsubscribe-Post is what tells a mail client it may unsubscribe with a
// single POST, and its presence is what mailbox providers look for.
func Headers(link string) (unsubscribe, post string) {
	return "<" + link + ">", "List-Unsubscribe=One-Click"
}

func payloadOf(messageID, address string, expiry int64) string {
	return fmt.Sprintf("%s\x00%s\x00%d", messageID, strings.ToLower(strings.TrimSpace(address)), expiry)
}

func mac(secret []byte, payload string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(payload))
	return m.Sum(nil)
}
