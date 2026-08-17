// Package crypto holds the envelope encryption used for data at rest.
//
// It exists as its own package because more than one kind of secret needs the
// same treatment — signing keys and recipient addresses — and a second
// implementation of the same primitive is a second chance to get it wrong.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	ErrNoPlaintext   = errors.New("nothing to encrypt")
	ErrBadCiphertext = errors.New("value could not be decrypted")
)

// Keeper wraps and unwraps values. A KMS-backed implementation swaps in
// without touching callers, which is why callers depend on this and not on the
// envelope below.
type Keeper interface {
	Wrap(plaintext []byte) ([]byte, error)
	Unwrap(ciphertext []byte) ([]byte, error)
}

// Envelope encrypts with AES-256-GCM under a master key held outside the
// database. It moves a secret from "readable in the database" to "readable
// only with the master key", which is the property that matters when a backup,
// a replica, or a query log leaks.
type Envelope struct {
	aead cipher.AEAD
}

func NewEnvelope(masterKey []byte) (*Envelope, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating gcm: %w", err)
	}
	return &Envelope{aead: aead}, nil
}

func (e *Envelope) Wrap(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrNoPlaintext
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *Envelope) Unwrap(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < e.aead.NonceSize() {
		return nil, ErrBadCiphertext
	}
	nonce, body := ciphertext[:e.aead.NonceSize()], ciphertext[e.aead.NonceSize():]
	plaintext, err := e.aead.Open(nil, nonce, body, nil)
	if err != nil {
		// Deliberately opaque: which of tampering, a wrong key, or corruption
		// occurred is not something a caller should learn.
		return nil, ErrBadCiphertext
	}
	return plaintext, nil
}
