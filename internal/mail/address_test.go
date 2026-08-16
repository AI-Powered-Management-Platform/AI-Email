package mail

import (
	"strings"
	"testing"
)

func TestHeaderInjectionIsRejected(t *testing.T) {
	payloads := map[string]string{
		"bare LF":      "Subject\nBcc: victim@example.com",
		"bare CR":      "Subject\rBcc: victim@example.com",
		"CRLF":         "Subject\r\nBcc: victim@example.com",
		"encoded null": "Subject\x00",
		"vertical tab": "Subject\x0b",
		"form feed":    "Subject\x0c",
		"DEL":          "Subject\x7f",
	}
	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			if !ContainsControl(payload) {
				t.Fatalf("control character not detected in %q", payload)
			}
			if err := ValidateSubject(payload); err == nil {
				t.Fatal("subject validation accepted an injected header")
			}
			if _, err := CleanHeaderValue("X-Test", payload); err == nil {
				t.Fatal("header validation accepted an injected value")
			}
			if _, err := ParseAddress("user@example.com" + payload); err == nil {
				t.Fatal("address parsing accepted a control character")
			}
		})
	}
}

func TestTabIsAllowedBecauseItIsLegalFolding(t *testing.T) {
	if ContainsControl("a\tb") {
		t.Fatal("tab must be permitted inside header values")
	}
}

func TestParseAddressAcceptsRealAddresses(t *testing.T) {
	cases := []string{
		"user@example.com",
		"Display Name <user@example.com>",
		"first.last+tag@sub.example.co.uk",
	}
	for _, in := range cases {
		addr, err := ParseAddress(in)
		if err != nil {
			t.Fatalf("%q should parse: %v", in, err)
		}
		if addr.Domain == "" || !strings.Contains(addr.Email, "@") {
			t.Fatalf("%q parsed into %+v", in, addr)
		}
	}
}

func TestParseAddressRejectsRubbish(t *testing.T) {
	for _, in := range []string{"", "not-an-address", "@example.com", "user@", "user@ example.com"} {
		if _, err := ParseAddress(in); err == nil {
			t.Errorf("%q should have been rejected", in)
		}
	}
}

func TestRecipientCapAndDeduplication(t *testing.T) {
	many := make([]string, MaxRecipients+1)
	for i := range many {
		many[i] = "user@example.com"
	}
	if _, err := ParseRecipients(many); err == nil {
		t.Fatal("exceeding the recipient cap must be rejected")
	}

	got, err := ParseRecipients([]string{"a@example.com", "A@Example.com", "b@example.com"})
	if err != nil {
		t.Fatalf("valid recipients rejected: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("duplicate recipients should collapse, got %v", got)
	}
}

func TestEmptyRecipientsRejected(t *testing.T) {
	if _, err := ParseRecipients(nil); err == nil {
		t.Fatal("a message with no recipients must be rejected")
	}
}

func TestKhmerSubjectIsAccepted(t *testing.T) {
	if err := ValidateSubject("ការបញ្ជាទិញរបស់អ្នក"); err != nil {
		t.Fatalf("Khmer subject must be accepted: %v", err)
	}
}

func TestSubjectLengthIsBounded(t *testing.T) {
	if err := ValidateSubject(strings.Repeat("a", MaxSubjectLength+1)); err == nil {
		t.Fatal("an over-long subject must be rejected")
	}
	if err := ValidateSubject("   "); err == nil {
		t.Fatal("a blank subject must be rejected")
	}
}

func TestCustomHeadersMustBeNamespaced(t *testing.T) {
	if err := ValidateCustomHeader("Bcc", "victim@example.com"); err == nil {
		t.Fatal("a caller must not set arbitrary headers")
	}
	if err := ValidateCustomHeader("X-Campaign", "spring"); err != nil {
		t.Fatalf("an X- header should be allowed: %v", err)
	}
	if err := ValidateCustomHeader("X-Bad\r\nBcc", "x"); err == nil {
		t.Fatal("a header name with a control character must be rejected")
	}
}
