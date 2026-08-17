package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func newKeeper(t *testing.T) *Envelope {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("key: %v", err)
	}
	e, err := NewEnvelope(key)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return e
}

func TestRoundTrip(t *testing.T) {
	e := newKeeper(t)
	plaintext := []byte(`["alice@example.org","bob@example.org"]`)

	sealed, err := e.Wrap(plaintext)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("the ciphertext contains its own plaintext")
	}
	if bytes.Contains(sealed, []byte("alice@example.org")) {
		t.Fatal("a recipient address is readable in the ciphertext")
	}

	opened, err := e.Unwrap(sealed)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("round trip changed the value: %q", opened)
	}
}

func TestSameValueEncryptsDifferentlyEachTime(t *testing.T) {
	e := newKeeper(t)
	plaintext := []byte("user@example.org")

	first, _ := e.Wrap(plaintext)
	second, _ := e.Wrap(plaintext)

	// Identical ciphertexts would let anyone with database access tell which
	// rows share a recipient without decrypting anything.
	if bytes.Equal(first, second) {
		t.Fatal("encrypting the same value twice produced identical ciphertext")
	}
}

func TestAnotherKeyCannotOpenIt(t *testing.T) {
	sealed, err := newKeeper(t).Wrap([]byte("user@example.org"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, err := newKeeper(t).Unwrap(sealed); !errors.Is(err, ErrBadCiphertext) {
		t.Fatalf("a different key must not decrypt, got %v", err)
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	e := newKeeper(t)
	sealed, err := e.Wrap([]byte("user@example.org"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	for i := range sealed {
		tampered := append([]byte(nil), sealed...)
		tampered[i] ^= 0x01
		if _, err := e.Unwrap(tampered); err == nil {
			t.Fatalf("authenticated encryption accepted a modification at byte %d", i)
		}
		if i > 40 {
			break
		}
	}
}

func TestTruncatedCiphertextIsRejected(t *testing.T) {
	e := newKeeper(t)
	sealed, _ := e.Wrap([]byte("user@example.org"))

	for _, n := range []int{0, 1, 5, 11} {
		if _, err := e.Unwrap(sealed[:n]); err == nil {
			t.Errorf("a %d byte value must not decrypt", n)
		}
	}
}

func TestMasterKeyLengthIsEnforced(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewEnvelope(make([]byte, n)); err == nil {
			t.Errorf("a %d byte master key must be rejected", n)
		}
	}
}

func TestEmptyPlaintextIsRejected(t *testing.T) {
	if _, err := newKeeper(t).Wrap(nil); !errors.Is(err, ErrNoPlaintext) {
		t.Fatal("wrapping nothing should be an error, not an empty ciphertext")
	}
}
