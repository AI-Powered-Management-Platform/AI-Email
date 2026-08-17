// Package dkim generates, protects, and uses per-domain signing keys.
//
// A stolen signing key defeats every replay control: the attacker signs fresh
// mail that validates perfectly, and recovery means rotating DNS on every
// affected domain. So the key is never stored in clear, never leaves this
// package in clear, and has no export path anywhere in the API.
package dkim

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

var (
	ErrNoKeyMaterial = errors.New("no key material")
	ErrBadCiphertext = errors.New("key material could not be decrypted")
)

// Keeper wraps and unwraps signing keys. The local implementation below uses a
// master key from the environment; a KMS implementation swaps in without
// touching callers, which is why this is an interface from the start.
type Keeper interface {
	Wrap(plaintext []byte) ([]byte, error)
	Unwrap(ciphertext []byte) ([]byte, error)
}

// EnvelopeKeeper encrypts key material with AES-256-GCM under a master key.
//
// This is the self-hosted default. It moves the secret from "readable in the
// database" to "readable only with the master key", which is the property that
// matters when a backup or a query log leaks.
type EnvelopeKeeper struct {
	aead cipher.AEAD
}

func NewEnvelopeKeeper(masterKey []byte) (*EnvelopeKeeper, error) {
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
	return &EnvelopeKeeper{aead: aead}, nil
}

func (k *EnvelopeKeeper) Wrap(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrNoKeyMaterial
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (k *EnvelopeKeeper) Unwrap(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < k.aead.NonceSize() {
		return nil, ErrBadCiphertext
	}
	nonce, body := ciphertext[:k.aead.NonceSize()], ciphertext[k.aead.NonceSize():]
	plaintext, err := k.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, ErrBadCiphertext
	}
	return plaintext, nil
}

// KeyPair is a generated signing key. Private holds wrapped material only:
// the clear key exists in memory during signing and nowhere else.
type KeyPair struct {
	Selector      string
	Algorithm     string
	WrappedSecret []byte
	PublicRecord  string
}

// Generate creates an Ed25519 signing key.
//
// Ed25519 keeps the DNS record short enough to publish without splitting, and
// its signatures are small. RSA remains available because some receivers still
// require it.
func Generate(keeper Keeper, selector string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	wrapped, err := keeper.Wrap(priv)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		Selector:      selector,
		Algorithm:     "ed25519",
		WrappedSecret: wrapped,
		PublicRecord:  "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// GenerateRSA creates a 2048-bit RSA signing key for receivers that need one.
func GenerateRSA(keeper Keeper, selector string) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating rsa key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("encoding rsa key: %w", err)
	}
	wrapped, err := keeper.Wrap(der)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	return &KeyPair{
		Selector:      selector,
		Algorithm:     "rsa",
		WrappedSecret: wrapped,
		PublicRecord:  "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubDER),
	}, nil
}

// Signer holds an unwrapped key for the duration of a signing operation.
func unwrapSigner(keeper Keeper, algorithm string, wrapped []byte) (crypto.Signer, error) {
	material, err := keeper.Unwrap(wrapped)
	if err != nil {
		return nil, err
	}

	switch algorithm {
	case "ed25519":
		if len(material) != ed25519.PrivateKeySize {
			return nil, ErrBadCiphertext
		}
		return ed25519.PrivateKey(material), nil
	case "rsa":
		key, err := x509.ParsePKCS8PrivateKey(material)
		if err != nil {
			return nil, ErrBadCiphertext
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, ErrBadCiphertext
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unknown signing algorithm %q", algorithm)
	}
}

// DNSRecordName is where the public key must be published.
func DNSRecordName(selector, domain string) string {
	return selector + "._domainkey." + domain
}
