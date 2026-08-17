package dkim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// SignatureLifetime is the x= expiry written into every signature.
//
// DKIM signs the message, not the destination, so a captured message can be
// replayed to millions of addresses with our tenant's signature intact and
// valid. A short expiry is the control that limits how long a captured message
// remains useful. Minutes, not days.
const SignatureLifetime = 30 * time.Minute

// OversignedHeaders are signed one more time than they appear.
//
// Signing a header that is absent, or signing it twice, prevents an attacker
// from *adding* one to a captured message: any addition breaks the signature
// rather than riding along inside it. Bcc appears here precisely because it is
// normally absent.
var OversignedHeaders = []string{
	"From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID",
	"Reply-To", "Content-Type", "Content-Transfer-Encoding",
	"MIME-Version", "Sender", "List-Unsubscribe", "List-Unsubscribe-Post",
}

type Key struct {
	Domain    string
	Selector  string
	Algorithm string
	Wrapped   []byte
}

type Signer struct {
	keeper Keeper
}

func NewSigner(keeper Keeper) *Signer {
	return &Signer{keeper: keeper}
}

// Sign returns the message with a DKIM-Signature header prepended.
//
// The key is unwrapped for this call and discarded with it. There is
// deliberately no method that returns key material to a caller.
func (s *Signer) Sign(ctx context.Context, key Key, message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("nothing to sign")
	}

	signer, err := unwrapSigner(s.keeper, key.Algorithm, key.Wrapped)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	options := &dkim.SignOptions{
		Domain:     key.Domain,
		Selector:   key.Selector,
		Signer:     signer,
		HeaderKeys: OversignedHeaders,
		Expiration: now.Add(SignatureLifetime),
	}

	switch key.Algorithm {
	case "ed25519":
		options.HeaderCanonicalization = dkim.CanonicalizationRelaxed
		options.BodyCanonicalization = dkim.CanonicalizationRelaxed
	case "rsa":
		options.HeaderCanonicalization = dkim.CanonicalizationRelaxed
		options.BodyCanonicalization = dkim.CanonicalizationRelaxed
	}

	var out bytes.Buffer
	if err := dkim.Sign(&out, bytes.NewReader(message), options); err != nil {
		return nil, fmt.Errorf("signing message: %w", err)
	}

	signed := out.Bytes()
	if err := assertNoBodyLengthTag(signed); err != nil {
		return nil, err
	}
	return signed, nil
}

// assertNoBodyLengthTag refuses to emit a signature carrying l=.
//
// The body-length tag tells a verifier to check only the first N bytes, which
// lets an attacker append arbitrary content to a captured message and keep the
// signature valid. We never want it, so rather than trusting the library's
// defaults to stay unchanged, every signature is checked before it leaves.
func assertNoBodyLengthTag(signed []byte) error {
	header, _, found := bytes.Cut(signed, []byte("\r\n\r\n"))
	if !found {
		header = signed
	}
	for _, field := range strings.Split(string(header), "\r\n") {
		if !strings.HasPrefix(strings.ToLower(field), "dkim-signature:") {
			continue
		}
		for _, tag := range strings.Split(field, ";") {
			if strings.HasPrefix(strings.TrimSpace(tag), "l=") {
				return fmt.Errorf("refusing to emit a DKIM signature with a body-length tag")
			}
		}
	}
	return nil
}

// Verify checks a signed message, used by tests and by the self-check that
// runs before a domain is allowed to send.
func Verify(message []byte) ([]*dkim.Verification, error) {
	return dkim.Verify(bytes.NewReader(message))
}

// VerifyWith checks a signed message against a caller-supplied resolver, so a
// test can verify without publishing DNS.
func VerifyWith(message []byte, lookup func(string) ([]string, error)) ([]*dkim.Verification, error) {
	options := &dkim.VerifyOptions{LookupTXT: lookup}
	return dkim.VerifyWithOptions(bytes.NewReader(message), options)
}

var _ io.Reader = (*bytes.Reader)(nil)
