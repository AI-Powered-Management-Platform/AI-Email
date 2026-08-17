package dkim

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/mail"
)

func testKeeper(t *testing.T) *EnvelopeKeeper {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("master key: %v", err)
	}
	k, err := NewEnvelopeKeeper(master)
	if err != nil {
		t.Fatalf("keeper: %v", err)
	}
	return k
}

func testMessage(t *testing.T) []byte {
	t.Helper()
	msg, err := mail.Build(mail.Envelope{
		MessageID: "01TEST@example.com",
		From:      "noreply@example.com",
		To:        []string{"user@example.org"},
		Subject:   "ការបញ្ជាទិញរបស់អ្នក",
		HTML:      "<p>Hello</p>",
		Date:      time.Now(),
	})
	if err != nil {
		t.Fatalf("building message: %v", err)
	}
	return msg
}

func TestWrappedKeyIsNotReadable(t *testing.T) {
	keeper := testKeeper(t)
	pair, err := Generate(keeper, "s1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	plain, err := keeper.Unwrap(pair.WrappedSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if bytes.Contains(pair.WrappedSecret, plain) {
		t.Fatal("the wrapped key contains its own plaintext")
	}
	if !strings.HasPrefix(pair.PublicRecord, "v=DKIM1;") {
		t.Fatalf("public record is malformed: %q", pair.PublicRecord)
	}
	if strings.Contains(pair.PublicRecord, string(plain)) {
		t.Fatal("the public record leaks private key material")
	}
}

func TestWrappedKeyCannotBeOpenedWithAnotherMasterKey(t *testing.T) {
	pair, err := Generate(testKeeper(t), "s1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := testKeeper(t).Unwrap(pair.WrappedSecret); err == nil {
		t.Fatal("key material must not open under a different master key")
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	keeper := testKeeper(t)
	pair, err := Generate(keeper, "s1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	tampered := append([]byte(nil), pair.WrappedSecret...)
	tampered[len(tampered)-1] ^= 0xff

	if _, err := keeper.Unwrap(tampered); err == nil {
		t.Fatal("authenticated encryption must reject modified ciphertext")
	}
}

func TestSignedMessageVerifies(t *testing.T) {
	keeper := testKeeper(t)
	pair, err := Generate(keeper, "s1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	signed, err := NewSigner(keeper).Sign(context.Background(), Key{
		Domain: "example.com", Selector: pair.Selector, Algorithm: pair.Algorithm, Wrapped: pair.WrappedSecret,
	}, testMessage(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	lookup := func(name string) ([]string, error) {
		if name != DNSRecordName("s1", "example.com") {
			t.Errorf("unexpected lookup for %q", name)
		}
		return []string{pair.PublicRecord}, nil
	}
	results, err := VerifyWith(signed, lookup)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one signature, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("signature did not verify: %v", results[0].Err)
	}
}

// A tampered body must break the signature: this is the property the whole
// scheme exists for.
func TestModifiedBodyBreaksTheSignature(t *testing.T) {
	keeper := testKeeper(t)
	pair, _ := Generate(keeper, "s1")

	signed, err := NewSigner(keeper).Sign(context.Background(), Key{
		Domain: "example.com", Selector: "s1", Algorithm: pair.Algorithm, Wrapped: pair.WrappedSecret,
	}, testMessage(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tampered := bytes.Replace(signed, []byte("Hello"), []byte("Goodb"), 1)
	if bytes.Equal(tampered, signed) {
		t.Skip("test message did not contain the expected body text")
	}

	results, err := VerifyWith(tampered, func(string) ([]string, error) {
		return []string{pair.PublicRecord}, nil
	})
	if err == nil && len(results) > 0 && results[0].Err == nil {
		t.Fatal("a modified body must break the signature")
	}
}

// Appending content must break the signature. It only does so because we never
// emit an l= tag; with one, appended text would ride along on a valid
// signature.
func TestAppendedContentBreaksTheSignature(t *testing.T) {
	keeper := testKeeper(t)
	pair, _ := Generate(keeper, "s1")

	signed, err := NewSigner(keeper).Sign(context.Background(), Key{
		Domain: "example.com", Selector: "s1", Algorithm: pair.Algorithm, Wrapped: pair.WrappedSecret,
	}, testMessage(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	appended := append(append([]byte(nil), signed...), []byte("\r\nSPAM PAYLOAD APPENDED\r\n")...)
	results, err := VerifyWith(appended, func(string) ([]string, error) {
		return []string{pair.PublicRecord}, nil
	})
	if err == nil && len(results) > 0 && results[0].Err == nil {
		t.Fatal("appended content must break the signature; check that l= is absent")
	}
}

func TestSignatureCarriesAnExpiryAndNoBodyLengthTag(t *testing.T) {
	keeper := testKeeper(t)
	pair, _ := Generate(keeper, "s1")

	signed, err := NewSigner(keeper).Sign(context.Background(), Key{
		Domain: "example.com", Selector: "s1", Algorithm: pair.Algorithm, Wrapped: pair.WrappedSecret,
	}, testMessage(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	header := string(signed[:min(len(signed), 2000)])
	if !strings.Contains(header, "DKIM-Signature:") {
		t.Fatal("no DKIM-Signature header was written")
	}
	if !strings.Contains(header, "x=") {
		t.Fatal("signature must carry a short expiry (x=) to limit replay")
	}
	for _, tag := range strings.Split(header, ";") {
		if strings.HasPrefix(strings.TrimSpace(tag), "l=") {
			t.Fatal("signature must never carry a body-length tag")
		}
	}
}

func TestOversigningCoversHeadersThatAreNormallyAbsent(t *testing.T) {
	// Bcc must be in the oversigned set: adding one to a captured message is
	// exactly how a replayed message reaches new recipients.
	var found bool
	for _, h := range OversignedHeaders {
		if h == "Bcc" {
			found = true
		}
	}
	if !found {
		t.Fatal("Bcc must be oversigned so it cannot be added after signing")
	}
}

func TestSigningRejectsAnEmptyMessage(t *testing.T) {
	keeper := testKeeper(t)
	pair, _ := Generate(keeper, "s1")
	_, err := NewSigner(keeper).Sign(context.Background(), Key{
		Domain: "example.com", Selector: "s1", Algorithm: pair.Algorithm, Wrapped: pair.WrappedSecret,
	}, nil)
	if err == nil {
		t.Fatal("signing nothing must fail")
	}
}

func TestRSAKeysAlsoSignAndVerify(t *testing.T) {
	keeper := testKeeper(t)
	pair, err := GenerateRSA(keeper, "rsa1")
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}

	signed, err := NewSigner(keeper).Sign(context.Background(), Key{
		Domain: "example.com", Selector: "rsa1", Algorithm: pair.Algorithm, Wrapped: pair.WrappedSecret,
	}, testMessage(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	results, err := VerifyWith(signed, func(string) ([]string, error) {
		return []string{pair.PublicRecord}, nil
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(results) == 0 || results[0].Err != nil {
		t.Fatalf("rsa signature did not verify: %+v", results)
	}
}
