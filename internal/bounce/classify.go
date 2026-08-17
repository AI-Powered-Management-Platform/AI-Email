// Package bounce classifies delivery failures.
//
// Getting this wrong is expensive in both directions. Treating a permanent
// failure as temporary means retrying an address that will never accept mail,
// which mailbox providers read as not listening. Treating a temporary failure
// as permanent means suppressing a real customer over a full mailbox.
package bounce

import (
	"errors"
	"fmt"
	"strings"
)

type Kind int

const (
	// Unknown means the response could not be classified. It is treated as
	// temporary, because retrying costs a little and suppressing a real
	// recipient costs a customer.
	Unknown Kind = iota
	Soft
	Hard
	Complaint
)

func (k Kind) String() string {
	switch k {
	case Soft:
		return "soft"
	case Hard:
		return "hard"
	case Complaint:
		return "complaint"
	default:
		return "unknown"
	}
}

// Suppresses reports whether this outcome must stop future sending.
func (k Kind) Suppresses() bool { return k == Hard || k == Complaint }

type Result struct {
	Kind      Kind
	Status    string
	Reason    string
	Retryable bool
}

// Suppresses reports whether this outcome must stop future sending to the
// address.
func (r Result) Suppresses() bool { return r.Kind.Suppresses() }

// hardStatus lists enhanced status codes that mean the address itself is bad.
// Anything not listed here is not assumed permanent.
var hardStatus = map[string]string{
	"5.1.1":  "no such user",
	"5.1.2":  "no such domain",
	"5.1.3":  "invalid address syntax",
	"5.1.6":  "mailbox has moved",
	"5.1.10": "no such user, address rejected",
	"5.2.1":  "mailbox disabled",
	"5.4.4":  "unable to route to destination",
	"5.5.4":  "invalid recipient",
	"5.7.27": "sender address rejected by policy",
}

// softStatus lists codes that are explicitly temporary even when they arrive
// with a 5xx-looking shape.
var softStatus = map[string]string{
	"4.2.2":  "mailbox full",
	"4.2.1":  "mailbox disabled temporarily",
	"4.3.2":  "system not accepting messages",
	"4.4.1":  "no answer from host",
	"4.4.2":  "bad connection",
	"4.5.3":  "too many recipients",
	"4.7.0":  "policy deferral, often greylisting",
	"4.7.1":  "delivery not authorised, try later",
	"4.7.28": "rate limited by the destination",
	"5.2.2":  "mailbox full",
}

// complaintPhrases mark a recipient reporting the message as spam. A complaint
// suppresses immediately: continuing to send to someone who reported us is the
// fastest way to lose a sending reputation.
var complaintPhrases = []string{
	"abuse report", "feedback-type: abuse", "this is an email abuse report",
	"complaint about message", "spam report",
}

var ErrTooLarge = errors.New("report is too large to parse")

// MaxReportBytes caps what is parsed. Bounce reports are attacker-authored:
// anyone can send us mail, so an unbounded parse is an invitation.
const MaxReportBytes = 1 << 20

// Classify reads an SMTP response or DSN body.
func Classify(response string) Result {
	if len(response) > MaxReportBytes {
		response = response[:MaxReportBytes]
	}
	lowered := strings.ToLower(response)

	for _, phrase := range complaintPhrases {
		if strings.Contains(lowered, phrase) {
			return Result{Kind: Complaint, Reason: "recipient reported the message as spam"}
		}
	}

	if status, ok := findEnhancedStatus(response); ok {
		if reason, hard := hardStatus[status]; hard {
			return Result{Kind: Hard, Status: status, Reason: reason}
		}
		if reason, soft := softStatus[status]; soft {
			return Result{Kind: Soft, Status: status, Reason: reason, Retryable: true}
		}
		switch status[0] {
		case '5':
			return Result{Kind: Hard, Status: status, Reason: "permanent failure reported by the destination"}
		case '4':
			return Result{Kind: Soft, Status: status, Reason: "temporary failure reported by the destination", Retryable: true}
		}
	}

	if code, ok := findReplyCode(response); ok {
		switch {
		case code >= 500:
			return Result{Kind: Hard, Status: fmt.Sprint(code), Reason: "permanent failure reported by the destination"}
		case code >= 400:
			return Result{Kind: Soft, Status: fmt.Sprint(code), Reason: "temporary failure reported by the destination", Retryable: true}
		}
	}

	return Result{Kind: Unknown, Reason: "could not classify the response", Retryable: true}
}

// findEnhancedStatus extracts an RFC 3463 code such as 5.1.1.
func findEnhancedStatus(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '4' && s[i] != '5' {
			continue
		}
		if i > 0 && isDigit(s[i-1]) {
			continue
		}
		rest := s[i:]
		status, ok := parseStatus(rest)
		if ok {
			return status, true
		}
	}
	return "", false
}

func parseStatus(s string) (string, bool) {
	var parts []string
	start := 0
	for section := 0; section < 3; section++ {
		end := start
		for end < len(s) && isDigit(s[end]) {
			end++
		}
		if end == start || end-start > 3 {
			return "", false
		}
		parts = append(parts, s[start:end])
		if section < 2 {
			if end >= len(s) || s[end] != '.' {
				return "", false
			}
			start = end + 1
		}
	}
	return strings.Join(parts, "."), true
}

// findReplyCode extracts a three digit SMTP reply code.
func findReplyCode(s string) (int, bool) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == '-'
	})
	for _, f := range fields {
		if len(f) != 3 || !isDigit(f[0]) || !isDigit(f[1]) || !isDigit(f[2]) {
			continue
		}
		code := int(f[0]-'0')*100 + int(f[1]-'0')*10 + int(f[2]-'0')
		if code >= 200 && code <= 599 {
			return code, true
		}
	}
	return 0, false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
