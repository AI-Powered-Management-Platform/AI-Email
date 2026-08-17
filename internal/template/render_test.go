package template

import (
	"errors"
	"strings"
	"testing"
)

func TestSubstitutesValues(t *testing.T) {
	got, err := Render("Hello {{ name }}, order {{order_id}}.",
		map[string]string{"name": "Sok", "order_id": "A-42"}, false)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != "Hello Sok, order A-42." {
		t.Fatalf("unexpected output: %q", got)
	}
}

// The whole reason this is not a template engine: no expression may reach
// anything the caller did not pass in.
func TestNoAttributeOrCallSyntaxIsAccepted(t *testing.T) {
	hostile := []string{
		"{{ user.password }}",
		"{{ user['password'] }}",
		"{{ config.items() }}",
		"{{ ''.__class__.__mro__ }}",
		"{{ 7*7 }}",
		"{{ range(10) }}",
		"{{ self._TemplateReference__context }}",
		"{{ request.application.__globals__ }}",
		"{{ name|upper }}",
		"{{ name if name else 'x' }}",
	}
	for _, tmpl := range hostile {
		if _, err := Render(tmpl, map[string]string{"name": "Sok"}, false); err == nil {
			t.Errorf("%q was accepted; only plain names may be used", tmpl)
		} else {
			var invalid *InvalidNameError
			if !errors.As(err, &invalid) {
				t.Errorf("%q should be rejected as an invalid name, got %v", tmpl, err)
			}
		}
	}
}

// A value must never be rescanned, or data could introduce tags and read
// variables it was never given.
func TestSubstitutedValuesAreNotRescanned(t *testing.T) {
	got, err := Render("Hi {{name}}", map[string]string{
		"name":   "{{secret}}",
		"secret": "SHOULD NOT APPEAR",
	}, false)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(got, "SHOULD NOT APPEAR") {
		t.Fatalf("a value was rescanned as a template: %q", got)
	}
	if got != "Hi {{secret}}" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestValuesAreEscapedInHTML(t *testing.T) {
	got, err := Render("<p>Hi {{name}}</p>", map[string]string{"name": `<script>alert(1)</script>`}, true)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(got, "<script>") {
		t.Fatalf("a value became markup: %q", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Fatalf("expected the value escaped, got %q", got)
	}
}

func TestPlainTextIsNotEscaped(t *testing.T) {
	got, err := Render("Hi {{name}}", map[string]string{"name": "Sok & Co"}, false)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != "Hi Sok & Co" {
		t.Fatalf("the text part should not be escaped, got %q", got)
	}
}

// A missing value must stop the send. "Dear ," is already delivered by the
// time anyone notices.
func TestMissingVariableIsAnError(t *testing.T) {
	_, err := Render("Dear {{name}},", map[string]string{}, false)
	if err == nil {
		t.Fatal("a missing variable must not render as empty")
	}
	var unknown *UnknownVariableError
	if !errors.As(err, &unknown) || unknown.Name != "name" {
		t.Fatalf("expected an unknown variable error naming name, got %v", err)
	}
}

func TestUnclosedTagIsRejected(t *testing.T) {
	if _, err := Render("Hello {{name", map[string]string{"name": "x"}, false); !errors.Is(err, ErrUnclosedTag) {
		t.Fatalf("expected an unclosed tag error, got %v", err)
	}
}

func TestTemplateWithoutTagsPassesThrough(t *testing.T) {
	got, err := Render("no tags here", nil, false)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != "no tags here" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestLimitsAreEnforced(t *testing.T) {
	if _, err := Render(strings.Repeat("x", MaxTemplateBytes+1), nil, false); !errors.Is(err, ErrTemplateTooLarge) {
		t.Error("an oversized template must be rejected")
	}

	many := map[string]string{}
	for i := range MaxVariables + 1 {
		many[fmt_Sprintf(i)] = "v"
	}
	if _, err := Render("x", many, false); !errors.Is(err, ErrTooManyVariables) {
		t.Error("too many variables must be rejected")
	}

	// Expansion is where a small template becomes a huge message.
	big := strings.Repeat("y", 200_000)
	if _, err := Render("{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}", map[string]string{"a": big}, false); !errors.Is(err, ErrOutputTooLarge) {
		t.Error("expansion beyond the output cap must be rejected")
	}
}

func TestLongVariableNamesAreRejected(t *testing.T) {
	name := strings.Repeat("a", MaxVariableNameLen+1)
	if _, err := Render("{{"+name+"}}", map[string]string{name: "x"}, false); err == nil {
		t.Fatal("an over-long variable name must be rejected")
	}
}

func TestTagsListsWhatATemplateNeeds(t *testing.T) {
	names, err := Tags("Hi {{name}}, your {{item}} ships. Thanks {{name}}.")
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	if len(names) != 2 || names[0] != "name" || names[1] != "item" {
		t.Fatalf("unexpected tags: %v", names)
	}
}

func fmt_Sprintf(i int) string {
	return "v" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
}
