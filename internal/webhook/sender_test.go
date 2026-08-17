package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The guard must stop a real request, not merely a parsed string. httptest
// listens on loopback, which is exactly what a tenant would target to reach
// our internal network.
func TestSenderRefusesToReachLoopback(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := NewSender(5*time.Second).Send(context.Background(), srv.URL, []byte("secret"), []byte(`{}`))

	if reached {
		t.Fatal("the request reached a loopback server; the guard did not hold")
	}
	if res.Outcome != Drop {
		t.Fatalf("a blocked destination must be dropped, not retried: %+v", res)
	}
}

func TestSenderRefusesMetadataAddress(t *testing.T) {
	res := NewSender(2*time.Second).Send(context.Background(),
		"http://169.254.169.254/latest/meta-data/", []byte("secret"), []byte(`{}`))

	if res.Outcome != Drop {
		t.Fatalf("cloud metadata must be dropped, got %+v", res)
	}
}

func TestSenderRefusesNonHTTPScheme(t *testing.T) {
	res := NewSender(2*time.Second).Send(context.Background(),
		"file:///etc/passwd", []byte("secret"), []byte(`{}`))

	if res.Outcome != Drop {
		t.Fatalf("a file url must be dropped, got %+v", res)
	}
}

// A delivered request must carry a signature the receiver can check, so this
// asserts the receiving side of the contract too.
func TestDeliveredRequestCarriesAVerifiableSignature(t *testing.T) {
	const endpointSecret = "endpoint-secret-value"
	payload := []byte(`{"event_id":"e1","type":"email.sent"}`)

	var verifyErr error
	var sawDigest string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sawDigest = r.Header.Get("Content-Digest")

		// A receiver rebuilds the target from the request line, exactly as a
		// tenant's server would.
		target := "http://" + r.Host + r.URL.RequestURI()
		verifyErr = Verify(r.Method, target, body, []byte(endpointSecret),
			r.Header.Get("Signature-Input"), r.Header.Get("Signature"), time.Now())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// The guard blocks loopback, so the signature is exercised directly against
	// a request built the same way the sender builds it.
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	Sign(req, payload, []byte(endpointSecret), time.Now())

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("posting: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if verifyErr != nil {
		t.Fatalf("receiver could not verify the signature: %v", verifyErr)
	}
	if !strings.HasPrefix(sawDigest, "sha-256=:") {
		t.Fatalf("receiver saw no content digest, got %q", sawDigest)
	}
}
