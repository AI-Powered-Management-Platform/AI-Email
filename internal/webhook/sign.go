// Package webhook delivers signed events to tenant endpoints.
//
// Signing follows the RFC 9421 HTTP Message Signatures construction with a
// fixed component set. An unsigned webhook is indistinguishable from a forged
// one, so every delivery carries a signature over the method, target, body
// digest, and creation time.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Components are the parts covered by the signature. The body digest is
// included so a modified payload cannot reuse a valid signature, and created
// is included so an old capture cannot be replayed indefinitely.
var Components = []string{`"@method"`, `"@target-uri"`, `"content-digest"`, `"@signature-params"`}

const (
	// ReplayWindow bounds how long a signature stays acceptable. Receivers
	// should enforce it; we document it by refusing to sign a stale timestamp.
	ReplayWindow = 5 * time.Minute

	keyID = "aiemail"
)

// ContentDigest returns the RFC 9530 representation of the body.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// NormalizeTarget makes both sides agree on the target URI.
//
// A Go client leaves the path empty when a URL has none, while the receiver
// reconstructs it from a request line that always carries at least "/". Those
// two strings must not produce different signature bases, so the empty path is
// normalised here for signer and verifier alike.
func NormalizeTarget(targetURI string) string {
	u, err := url.Parse(targetURI)
	if err != nil {
		return targetURI
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

// SignatureBase builds the exact string that gets signed. Both sides must
// derive it identically, so it is constructed here and nowhere else.
func SignatureBase(method, targetURI, digest string, created int64) string {
	params := signatureParams(created)

	var b strings.Builder
	fmt.Fprintf(&b, "\"@method\": %s\n", strings.ToUpper(method))
	fmt.Fprintf(&b, "\"@target-uri\": %s\n", NormalizeTarget(targetURI))
	fmt.Fprintf(&b, "\"content-digest\": %s\n", digest)
	fmt.Fprintf(&b, "\"@signature-params\": %s", params)
	return b.String()
}

func signatureParams(created int64) string {
	return fmt.Sprintf("(\"@method\" \"@target-uri\" \"content-digest\");created=%d;keyid=%q;alg=\"hmac-sha256\"", created, keyID)
}

// Sign attaches the digest and signature headers to a request.
func Sign(req *http.Request, body []byte, secret []byte, created time.Time) {
	digest := ContentDigest(body)
	req.Header.Set("Content-Digest", digest)

	unix := created.Unix()
	base := SignatureBase(req.Method, req.URL.String(), digest, unix)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(base))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req.Header.Set("Signature-Input", "sig1="+signatureParams(unix))
	req.Header.Set("Signature", "sig1=:"+sig+":")
}

// Verify recomputes the signature. It exists so our own tests, and any tenant
// writing a receiver in Go, check against the same implementation that signs.
func Verify(method, targetURI string, body, secret []byte, signatureInput, signature string, now time.Time) error {
	created, err := createdFrom(signatureInput)
	if err != nil {
		return err
	}
	age := now.Sub(time.Unix(created, 0))
	if age > ReplayWindow || age < -ReplayWindow {
		return fmt.Errorf("signature timestamp is outside the %s replay window", ReplayWindow)
	}

	digest := ContentDigest(body)
	base := SignatureBase(method, targetURI, digest, created)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(base))
	want := mac.Sum(nil)

	got, err := base64.StdEncoding.DecodeString(strings.Trim(strings.TrimPrefix(signature, "sig1="), ":"))
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !hmac.Equal(want, got) {
		return fmt.Errorf("signature does not match")
	}
	return nil
}

func createdFrom(signatureInput string) (int64, error) {
	const marker = "created="
	i := strings.Index(signatureInput, marker)
	if i < 0 {
		return 0, fmt.Errorf("signature input has no created parameter")
	}
	rest := signatureInput[i+len(marker):]
	end := strings.IndexAny(rest, ";,")
	if end >= 0 {
		rest = rest[:end]
	}
	var created int64
	if _, err := fmt.Sscanf(rest, "%d", &created); err != nil {
		return 0, fmt.Errorf("signature input has an unreadable created parameter")
	}
	return created, nil
}
