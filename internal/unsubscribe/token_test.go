package unsubscribe

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var secret = DeriveSecret([]byte("a-master-key-for-tests-32-bytes!!"))

func TestRoundTrip(t *testing.T) {
	now := time.Now()
	token := Sign(secret, "01MSG", "User@Example.org", now)

	got, err := Verify(secret, token, now)
	if err != nil {
		t.Fatalf("a fresh token must verify: %v", err)
	}
	if got.MessageID != "01MSG" {
		t.Fatalf("message id lost: %q", got.MessageID)
	}
	// The address is normalised at signing so the same person is one identity.
	if got.Address != "user@example.org" {
		t.Fatalf("address should be normalised, got %q", got.Address)
	}
}

// A guessable or forgeable link would let one request unsubscribe an entire
// list.
func TestForgedTokensAreRejected(t *testing.T) {
	now := time.Now()
	valid := Sign(secret, "01MSG", "user@example.org", now)

	cases := map[string]string{
		"empty":            "",
		"no separator":     "abcdef",
		"payload only":     strings.Split(valid, ".")[0],
		"swapped halves":   strings.Split(valid, ".")[1] + "." + strings.Split(valid, ".")[0],
		"tampered payload": "aaaa." + strings.Split(valid, ".")[1],
		"tampered sig":     strings.Split(valid, ".")[0] + ".aaaa",
	}
	for name, token := range cases {
		if _, err := Verify(secret, token, now); err == nil {
			t.Errorf("%s: forged token was accepted", name)
		}
	}
}

func TestTokenFromAnotherDeploymentIsRejected(t *testing.T) {
	other := DeriveSecret([]byte("a-different-master-key-32-bytes!!"))
	token := Sign(other, "01MSG", "user@example.org", time.Now())

	if _, err := Verify(secret, token, time.Now()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a token signed elsewhere must not verify, got %v", err)
	}
}

func TestExpiredTokensAreRejected(t *testing.T) {
	signedAt := time.Now().Add(-Lifetime - time.Hour)
	token := Sign(secret, "01MSG", "user@example.org", signedAt)

	if _, err := Verify(secret, token, time.Now()); !errors.Is(err, ErrExpired) {
		t.Fatalf("an old link must expire, got %v", err)
	}
}

// One recipient's link must not unsubscribe another, or a single leaked
// message would compromise a whole list.
func TestTokensAreBoundToOneRecipient(t *testing.T) {
	now := time.Now()
	a := Sign(secret, "01MSG", "alice@example.org", now)
	b := Sign(secret, "01MSG", "bob@example.org", now)

	if a == b {
		t.Fatal("two recipients produced the same token")
	}
	got, err := Verify(secret, a, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Address == "bob@example.org" {
		t.Fatal("a token resolved to the wrong recipient")
	}
}

func TestDerivedSecretIsNotTheMasterKey(t *testing.T) {
	master := []byte("a-master-key-for-tests-32-bytes!!")
	derived := DeriveSecret(master)

	if string(derived) == string(master) {
		t.Fatal("the derived secret must not equal the master key")
	}
	if len(derived) != 32 {
		t.Fatalf("expected a 32 byte secret, got %d", len(derived))
	}
}

func TestHeadersDeclareOneClick(t *testing.T) {
	link := Link("https://mail.example.com", "tok")
	unsub, post := Headers(link)

	if unsub != "<https://mail.example.com/u/tok>" {
		t.Fatalf("unexpected List-Unsubscribe value: %q", unsub)
	}
	// Without this header a provider will not treat the link as one-click.
	if post != "List-Unsubscribe=One-Click" {
		t.Fatalf("unexpected List-Unsubscribe-Post value: %q", post)
	}
}

func TestLinkHandlesTrailingSlash(t *testing.T) {
	if got := Link("https://mail.example.com/", "tok"); got != "https://mail.example.com/u/tok" {
		t.Fatalf("unexpected link: %q", got)
	}
}
