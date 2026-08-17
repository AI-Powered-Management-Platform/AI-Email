package webhook

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

var secret = []byte("a-shared-endpoint-secret")

func signedRequest(t *testing.T, body []byte, at time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://example.com/hooks/email", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	Sign(req, body, secret, at)
	return req
}

func TestSignedRequestVerifies(t *testing.T) {
	body := []byte(`{"type":"email.delivered"}`)
	now := time.Now()
	req := signedRequest(t, body, now)

	err := Verify(req.Method, req.URL.String(), body, secret,
		req.Header.Get("Signature-Input"), req.Header.Get("Signature"), now)
	if err != nil {
		t.Fatalf("a freshly signed request must verify: %v", err)
	}
}

func TestModifiedBodyFailsVerification(t *testing.T) {
	body := []byte(`{"amount":10}`)
	now := time.Now()
	req := signedRequest(t, body, now)

	tampered := []byte(`{"amount":1000}`)
	err := Verify(req.Method, req.URL.String(), tampered, secret,
		req.Header.Get("Signature-Input"), req.Header.Get("Signature"), now)
	if err == nil {
		t.Fatal("a modified body must not verify")
	}
}

func TestWrongSecretFailsVerification(t *testing.T) {
	body := []byte(`{"type":"email.sent"}`)
	now := time.Now()
	req := signedRequest(t, body, now)

	err := Verify(req.Method, req.URL.String(), body, []byte("someone-elses-secret"),
		req.Header.Get("Signature-Input"), req.Header.Get("Signature"), now)
	if err == nil {
		t.Fatal("a signature must not verify under a different secret")
	}
}

func TestDifferentTargetFailsVerification(t *testing.T) {
	body := []byte(`{"type":"email.sent"}`)
	now := time.Now()
	req := signedRequest(t, body, now)

	err := Verify(req.Method, "https://attacker.example/hooks/email", body, secret,
		req.Header.Get("Signature-Input"), req.Header.Get("Signature"), now)
	if err == nil {
		t.Fatal("a signature captured for one destination must not verify at another")
	}
}

func TestOldSignatureIsRejected(t *testing.T) {
	body := []byte(`{"type":"email.sent"}`)
	signedAt := time.Now().Add(-30 * time.Minute)
	req := signedRequest(t, body, signedAt)

	err := Verify(req.Method, req.URL.String(), body, secret,
		req.Header.Get("Signature-Input"), req.Header.Get("Signature"), time.Now())
	if err == nil {
		t.Fatal("a captured signature must expire")
	}
	if !strings.Contains(err.Error(), "replay window") {
		t.Fatalf("expected a replay window error, got %v", err)
	}
}

func TestFutureSignatureIsRejected(t *testing.T) {
	body := []byte(`{"type":"email.sent"}`)
	req := signedRequest(t, body, time.Now().Add(30*time.Minute))

	err := Verify(req.Method, req.URL.String(), body, secret,
		req.Header.Get("Signature-Input"), req.Header.Get("Signature"), time.Now())
	if err == nil {
		t.Fatal("a signature created in the future must be rejected")
	}
}

func TestHeadersAreSetInTheExpectedShape(t *testing.T) {
	body := []byte(`{}`)
	req := signedRequest(t, body, time.Now())

	if digest := req.Header.Get("Content-Digest"); !strings.HasPrefix(digest, "sha-256=:") {
		t.Fatalf("content digest should be RFC 9530 shaped, got %q", digest)
	}
	input := req.Header.Get("Signature-Input")
	for _, want := range []string{"sig1=", "created=", `keyid="aiemail"`, `alg="hmac-sha256"`} {
		if !strings.Contains(input, want) {
			t.Errorf("signature input should contain %q, got %q", want, input)
		}
	}
	if sig := req.Header.Get("Signature"); !strings.HasPrefix(sig, "sig1=:") {
		t.Fatalf("signature header should be a byte sequence, got %q", sig)
	}
}

func TestMalformedSignatureInputIsRejected(t *testing.T) {
	body := []byte(`{}`)
	for _, input := range []string{"", "sig1=()", "sig1=();created=abc"} {
		if err := Verify("POST", "https://example.com/h", body, secret, input, "sig1=:AAAA:", time.Now()); err == nil {
			t.Errorf("malformed signature input %q must be rejected", input)
		}
	}
}
