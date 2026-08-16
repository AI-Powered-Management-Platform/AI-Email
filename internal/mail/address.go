// Package mail validates and normalises message fields.
//
// Every value here reaches an SMTP conversation eventually, so the rules are
// deliberately strict: a carriage return that survives validation becomes a
// forged header at the far end.
package mail

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode"
)

// MaxRecipients caps one request. It bounds the damage a single stolen key
// does per call and keeps request handling predictable.
const MaxRecipients = 50

const MaxSubjectLength = 998

var (
	ErrControlCharacter  = errors.New("value contains a control character")
	ErrTooManyRecipients = fmt.Errorf("a message may not exceed %d recipients", MaxRecipients)
)

// ContainsControl reports characters that must never reach a header. It covers
// every C0 control plus DEL, not only CR and LF: NUL and friends break parsers
// further down the chain in less obvious ways.
func ContainsControl(s string) bool {
	for _, r := range s {
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// CleanHeaderValue rejects rather than sanitises. Silently stripping a
// character would let a caller believe a forged header was accepted.
func CleanHeaderValue(name, value string) (string, error) {
	if ContainsControl(value) {
		return "", fmt.Errorf("%s: %w", name, ErrControlCharacter)
	}
	return strings.TrimSpace(value), nil
}

type Address struct {
	Name   string
	Email  string
	Domain string
}

func ParseAddress(raw string) (Address, error) {
	if ContainsControl(raw) {
		return Address{}, ErrControlCharacter
	}
	// RFC 5322 permits folding whitespace inside an addr-spec, and the standard
	// parser silently normalises it away. Accepting that would make our view of
	// an address differ from the next hop's, which is the disagreement that
	// smuggling attacks live in. Require the addr-spec to be whitespace-free.
	if strings.ContainsAny(addrSpec(raw), " \t") {
		return Address{}, fmt.Errorf("%q is not a valid address", raw)
	}
	parsed, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return Address{}, fmt.Errorf("%q is not a valid address", raw)
	}
	at := strings.LastIndex(parsed.Address, "@")
	if at <= 0 || at == len(parsed.Address)-1 {
		return Address{}, fmt.Errorf("%q is not a valid address", raw)
	}
	domain := strings.ToLower(parsed.Address[at+1:])
	if strings.ContainsAny(domain, " \t") {
		return Address{}, fmt.Errorf("%q is not a valid address", raw)
	}
	return Address{Name: parsed.Name, Email: parsed.Address, Domain: domain}, nil
}

// addrSpec returns the part that must be whitespace-free: the text inside
// angle brackets when a display name is used, otherwise the whole value.
func addrSpec(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if open := strings.LastIndex(trimmed, "<"); open >= 0 {
		if close := strings.LastIndex(trimmed, ">"); close > open {
			return trimmed[open+1 : close]
		}
	}
	return trimmed
}

func ParseRecipients(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("at least one recipient is required")
	}
	if len(raw) > MaxRecipients {
		return nil, ErrTooManyRecipients
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, r := range raw {
		addr, err := ParseAddress(r)
		if err != nil {
			return nil, err
		}
		lowered := strings.ToLower(addr.Email)
		if seen[lowered] {
			continue
		}
		seen[lowered] = true
		out = append(out, addr.Email)
	}
	return out, nil
}

// ValidateSubject allows any printable Unicode, which is what makes Khmer
// subjects work, while refusing controls and over-long values.
func ValidateSubject(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("subject is required")
	}
	if ContainsControl(s) {
		return ErrControlCharacter
	}
	if len([]rune(s)) > MaxSubjectLength {
		return fmt.Errorf("subject may not exceed %d characters", MaxSubjectLength)
	}
	return nil
}

// ValidateCustomHeader permits only X- headers: anything else would let a
// caller overwrite the headers we sign and depend on.
func ValidateCustomHeader(name, value string) error {
	if name == "" {
		return errors.New("header name is required")
	}
	if !strings.HasPrefix(strings.ToUpper(name), "X-") {
		return fmt.Errorf("custom header %q must start with X-", name)
	}
	for _, r := range name {
		if r > unicode.MaxASCII || r <= 0x20 || r == ':' {
			return fmt.Errorf("header name %q contains an illegal character", name)
		}
	}
	if ContainsControl(value) {
		return fmt.Errorf("header %q: %w", name, ErrControlCharacter)
	}
	return nil
}
