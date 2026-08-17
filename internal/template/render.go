// Package template renders merge tags into a message.
//
// This is deliberately not a template engine. Tenant-authored templates are
// hostile input, and a real engine given hostile input is remote code
// execution: attribute walking reaches an object's internals, and sandbox
// escapes in general-purpose engines are published regularly.
//
// So there is no logic here at all. A tag names a value, the value is
// substituted, and nothing else happens. There are no conditionals, no loops,
// no function calls, no attribute or index access, and no way to reach
// anything the caller did not explicitly pass in.
package template

import (
	"errors"
	"fmt"
	"html"
	"strings"
	"unicode"
)

const (
	// MaxTemplateBytes bounds what will be scanned.
	MaxTemplateBytes = 512 << 10

	// MaxOutputBytes bounds the result. Substitution can expand input, so the
	// output needs its own limit rather than trusting the input's.
	MaxOutputBytes = 1 << 20

	MaxVariables       = 100
	MaxVariableNameLen = 64
	MaxTags            = 500
)

var (
	ErrTemplateTooLarge = fmt.Errorf("template exceeds %d bytes", MaxTemplateBytes)
	ErrOutputTooLarge   = fmt.Errorf("rendered output exceeds %d bytes", MaxOutputBytes)
	ErrTooManyTags      = fmt.Errorf("template contains more than %d tags", MaxTags)
	ErrTooManyVariables = fmt.Errorf("more than %d variables supplied", MaxVariables)
	ErrUnclosedTag      = errors.New("template has an unclosed tag")
)

// UnknownVariableError names a tag with no value.
//
// Rendering fails rather than substituting an empty string: a message that
// says "Dear ," has already been sent by the time anyone notices, and silence
// about a missing value is how that happens.
type UnknownVariableError struct{ Name string }

func (e *UnknownVariableError) Error() string {
	return fmt.Sprintf("template uses %q but no such variable was supplied", e.Name)
}

// InvalidNameError names a tag that is not a plain identifier.
type InvalidNameError struct{ Name string }

func (e *InvalidNameError) Error() string {
	return fmt.Sprintf("%q is not a valid variable name; only letters, digits and underscore are allowed", e.Name)
}

// Render substitutes {{ name }} tags.
//
// escape controls whether values are HTML-escaped, which is what keeps a
// recipient's name from becoming markup in the HTML part.
func Render(tmpl string, variables map[string]string, escape bool) (string, error) {
	if len(tmpl) > MaxTemplateBytes {
		return "", ErrTemplateTooLarge
	}
	if len(variables) > MaxVariables {
		return "", ErrTooManyVariables
	}
	for name := range variables {
		if err := validateName(name); err != nil {
			return "", err
		}
	}

	var out strings.Builder
	var tags int
	rest := tmpl

	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			out.WriteString(rest)
			break
		}
		out.WriteString(rest[:open])

		closing := strings.Index(rest[open:], "}}")
		if closing < 0 {
			return "", ErrUnclosedTag
		}

		name := strings.TrimSpace(rest[open+2 : open+closing])
		if err := validateName(name); err != nil {
			return "", err
		}

		value, ok := variables[name]
		if !ok {
			return "", &UnknownVariableError{Name: name}
		}

		// The substituted value is written straight to the output and never
		// rescanned. A value containing {{ something }} is therefore text, not
		// a tag, so data cannot introduce new tags.
		if escape {
			value = html.EscapeString(value)
		}
		out.WriteString(value)

		if tags++; tags > MaxTags {
			return "", ErrTooManyTags
		}
		if out.Len() > MaxOutputBytes {
			return "", ErrOutputTooLarge
		}
		rest = rest[open+closing+2:]
	}

	if out.Len() > MaxOutputBytes {
		return "", ErrOutputTooLarge
	}
	return out.String(), nil
}

// validateName allows only plain identifiers.
//
// This is what forecloses attribute access: there is no dot, no bracket, no
// call syntax, so a tag can only ever name a value the caller supplied.
func validateName(name string) error {
	if name == "" || len(name) > MaxVariableNameLen {
		return &InvalidNameError{Name: name}
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
		default:
			if unicode.IsSpace(r) {
				return &InvalidNameError{Name: name}
			}
			return &InvalidNameError{Name: name}
		}
	}
	return nil
}

// Tags lists the variable names a template uses, so a caller can see what a
// template needs without rendering it.
func Tags(tmpl string) ([]string, error) {
	if len(tmpl) > MaxTemplateBytes {
		return nil, ErrTemplateTooLarge
	}

	var names []string
	seen := map[string]bool{}
	rest := tmpl

	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			return names, nil
		}
		closing := strings.Index(rest[open:], "}}")
		if closing < 0 {
			return nil, ErrUnclosedTag
		}
		name := strings.TrimSpace(rest[open+2 : open+closing])
		if err := validateName(name); err != nil {
			return nil, err
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
		if len(names) > MaxTags {
			return nil, ErrTooManyTags
		}
		rest = rest[open+closing+2:]
	}
}
