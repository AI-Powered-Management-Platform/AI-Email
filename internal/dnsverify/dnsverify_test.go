package dnsverify

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type stubResolver struct {
	records map[string][]string
	err     error
}

func (s stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.records[name], nil
}

const token = "aiemail-verify=abc123"

func TestMatchingRecordVerifies(t *testing.T) {
	v := New(stubResolver{records: map[string][]string{
		"_aiemail.example.com": {token},
	}}, time.Second)

	if err := v.Verify(context.Background(), "example.com", token); err != nil {
		t.Fatalf("a published token must verify: %v", err)
	}
}

func TestVerificationIsCaseInsensitiveOnTheDomain(t *testing.T) {
	v := New(stubResolver{records: map[string][]string{
		"_aiemail.example.com": {token},
	}}, time.Second)

	if err := v.Verify(context.Background(), "EXAMPLE.COM", token); err != nil {
		t.Fatalf("domain case must not matter: %v", err)
	}
	if err := v.Verify(context.Background(), "example.com.", token); err != nil {
		t.Fatalf("a trailing dot must not matter: %v", err)
	}
}

func TestOtherRecordsAlongsideTheTokenStillVerify(t *testing.T) {
	v := New(stubResolver{records: map[string][]string{
		"_aiemail.example.com": {"v=spf1 -all", token, "unrelated"},
	}}, time.Second)

	if err := v.Verify(context.Background(), "example.com", token); err != nil {
		t.Fatalf("an unrelated neighbouring record must not break verification: %v", err)
	}
}

func TestMissingRecordIsReportedAsMissing(t *testing.T) {
	v := New(stubResolver{records: map[string][]string{}}, time.Second)

	err := v.Verify(context.Background(), "example.com", token)
	if !errors.Is(err, ErrNoRecord) {
		t.Fatalf("expected a missing-record error, got %v", err)
	}
	if Recheckable(err) {
		t.Fatal("a missing record is a real loss of proof, not a transient failure")
	}
}

func TestWrongTokenDoesNotVerify(t *testing.T) {
	v := New(stubResolver{records: map[string][]string{
		"_aiemail.example.com": {"aiemail-verify=someone-elses-token"},
	}}, time.Second)

	if err := v.Verify(context.Background(), "example.com", token); !errors.Is(err, ErrMismatch) {
		t.Fatalf("a different token must not verify, got %v", err)
	}
}

// A resolver outage must never be mistaken for a domain losing its proof, or a
// single DNS blip would suspend every sender at once.
func TestResolverOutageIsDistinctFromMissingProof(t *testing.T) {
	v := New(stubResolver{err: errors.New("server misbehaving")}, time.Second)

	err := v.Verify(context.Background(), "example.com", token)
	if errors.Is(err, ErrNoRecord) {
		t.Fatal("a lookup failure must not be reported as a missing record")
	}
	if !errors.Is(err, ErrLookupFail) {
		t.Fatalf("expected a lookup failure, got %v", err)
	}
	if !Recheckable(err) {
		t.Fatal("a lookup failure must be retried, not acted upon")
	}
}

func TestNotFoundFromResolverIsMissingProof(t *testing.T) {
	v := New(stubResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}}, time.Second)

	if err := v.Verify(context.Background(), "example.com", token); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("NXDOMAIN means the proof is absent, got %v", err)
	}
}

func TestEmptyInputsAreRejected(t *testing.T) {
	v := New(stubResolver{}, time.Second)
	if err := v.Verify(context.Background(), "", token); err == nil {
		t.Error("an empty domain must not verify")
	}
	if err := v.Verify(context.Background(), "example.com", ""); err == nil {
		t.Error("an empty token must not verify")
	}
}
