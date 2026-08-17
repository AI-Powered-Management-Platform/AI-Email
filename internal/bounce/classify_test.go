package bounce

import (
	"strings"
	"testing"
)

func TestHardBouncesSuppress(t *testing.T) {
	cases := []string{
		"550 5.1.1 <nobody@example.com>: Recipient address rejected: User unknown",
		"550 5.1.2 Host unknown",
		"550 5.2.1 mailbox disabled",
		"552 5.5.4 invalid recipient",
	}
	for _, in := range cases {
		got := Classify(in)
		if got.Kind != Hard {
			t.Errorf("%q should be hard, got %s", in, got.Kind)
		}
		if !got.Suppresses() {
			t.Errorf("%q should suppress the address", in)
		}
		if got.Retryable {
			t.Errorf("%q must not be retried", in)
		}
	}
}

// A full mailbox is the classic trap: it looks permanent and is not. Treating
// it as hard suppresses a real customer.
func TestFullMailboxIsNotPermanent(t *testing.T) {
	for _, in := range []string{
		"452 4.2.2 The email account that you tried to reach is over quota",
		"552 5.2.2 Mailbox full",
	} {
		got := Classify(in)
		if got.Kind != Soft {
			t.Errorf("%q should be soft, got %s", in, got.Kind)
		}
		if got.Suppresses() {
			t.Errorf("%q must not suppress a real recipient", in)
		}
	}
}

func TestGreylistingAndRateLimitsAreRetryable(t *testing.T) {
	for _, in := range []string{
		"450 4.7.0 Try again later, greylisted",
		"421 4.7.28 Our system has detected an unusual rate of unsolicited mail",
		"451 4.3.2 Service temporarily unavailable",
	} {
		got := Classify(in)
		if !got.Retryable || got.Kind != Soft {
			t.Errorf("%q should be a retryable soft failure, got %+v", in, got)
		}
	}
}

func TestComplaintsSuppressImmediately(t *testing.T) {
	report := strings.Join([]string{
		"Content-Type: message/feedback-report",
		"",
		"Feedback-Type: abuse",
		"User-Agent: SomeProvider/1.0",
		"Version: 1",
	}, "\r\n")

	got := Classify(report)
	if got.Kind != Complaint {
		t.Fatalf("an abuse report should be a complaint, got %s", got.Kind)
	}
	if !got.Suppresses() {
		t.Fatal("a complaint must suppress the address")
	}
}

// An unclassifiable response must be retried rather than suppressed: retrying
// costs a little, suppressing a real customer costs a customer.
func TestUnknownResponsesAreRetriedNotSuppressed(t *testing.T) {
	for _, in := range []string{"", "something went wrong", "connection reset"} {
		got := Classify(in)
		if got.Suppresses() {
			t.Errorf("%q must not suppress on an unclassified response", in)
		}
		if !got.Retryable {
			t.Errorf("%q should be retryable", in)
		}
	}
}

func TestBareReplyCodesStillClassify(t *testing.T) {
	if got := Classify("550 Requested action not taken"); got.Kind != Hard {
		t.Errorf("a bare 550 should be hard, got %s", got.Kind)
	}
	if got := Classify("451 Requested action aborted"); got.Kind != Soft {
		t.Errorf("a bare 451 should be soft, got %s", got.Kind)
	}
}

func TestUnlistedEnhancedCodesFollowTheirClass(t *testing.T) {
	if got := Classify("550 5.7.99 blocked by an unusual policy"); got.Kind != Hard {
		t.Errorf("an unlisted 5.x.x should be hard, got %s", got.Kind)
	}
	if got := Classify("450 4.9.99 something temporary"); got.Kind != Soft {
		t.Errorf("an unlisted 4.x.x should be soft, got %s", got.Kind)
	}
}

// Anyone can send us a bounce, so the parser must not be handed an unbounded
// body.
func TestOversizedReportsAreTruncatedNotParsedWhole(t *testing.T) {
	huge := strings.Repeat("x", MaxReportBytes*2) + " 550 5.1.1 user unknown"
	got := Classify(huge)
	if got.Kind == Hard {
		t.Fatal("content beyond the parse cap must not be read")
	}
}

func TestStatusCodeIsReported(t *testing.T) {
	got := Classify("550 5.1.1 user unknown")
	if got.Status != "5.1.1" {
		t.Fatalf("expected the enhanced status to be extracted, got %q", got.Status)
	}
	if got.Reason == "" {
		t.Fatal("a human-readable reason should be present")
	}
}
