// Package dnsverify proves that a sender controls the domain it sends from.
//
// Proof is re-checked continuously rather than once. Domains lapse, records
// get deleted, and ownership changes hands; a system that trusts a single past
// verification keeps sending for whoever holds the name today.
package dnsverify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// RecordPrefix is the label the proof record lives under.
const RecordPrefix = "_aiemail."

var (
	ErrNoRecord   = errors.New("no verification record found")
	ErrMismatch   = errors.New("verification record does not match")
	ErrLookupFail = errors.New("dns lookup failed")
)

type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type Verifier struct {
	resolver Resolver
	timeout  time.Duration
}

func New(resolver Resolver, timeout time.Duration) *Verifier {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Verifier{resolver: resolver, timeout: timeout}
}

// Verify reports whether the expected token is published for the domain.
//
// A lookup failure is returned distinctly from a missing record: a resolver
// outage must not be read as a domain losing its proof, or a DNS blip would
// suspend every sender at once.
func (v *Verifier) Verify(ctx context.Context, domain, expected string) error {
	if strings.TrimSpace(domain) == "" || strings.TrimSpace(expected) == "" {
		return ErrMismatch
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	name := RecordPrefix + strings.TrimSuffix(strings.ToLower(domain), ".")
	records, err := v.resolver.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return ErrNoRecord
		}
		return fmt.Errorf("%w: %v", ErrLookupFail, err)
	}
	if len(records) == 0 {
		return ErrNoRecord
	}

	for _, record := range records {
		// Resolvers split long strings into chunks; joining is safe because a
		// token contains no whitespace.
		if strings.TrimSpace(record) == expected {
			return nil
		}
	}
	return ErrMismatch
}

// Recheckable reports whether an error means the proof is genuinely gone, as
// opposed to temporarily unresolvable.
func Recheckable(err error) bool {
	return errors.Is(err, ErrLookupFail)
}
