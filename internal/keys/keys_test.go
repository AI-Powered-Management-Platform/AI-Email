package keys

import (
	"strings"
	"testing"
	"time"
)

func TestGeneratedKeysAreUniqueAndWellFormed(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		g, err := Generate()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if !strings.HasPrefix(g.Secret, LivePrefix) {
			t.Fatalf("secret must carry the scanner prefix, got %q", g.Secret)
		}
		if err := Parse(g.Secret); err != nil {
			t.Fatalf("generated key failed its own validation: %v", err)
		}
		if seen[g.Secret] {
			t.Fatal("generated a duplicate key")
		}
		seen[g.Secret] = true
	}
}

func TestDisplayNeverRevealsAUsableKey(t *testing.T) {
	g, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	shown := Display(g.Secret)
	if strings.Contains(g.Secret, shown) {
		t.Fatal("display fragment is a prefix of the real secret in full form")
	}
	if err := Parse(shown); err == nil {
		t.Fatal("the displayed fragment must not validate as a key")
	}
}

func TestHashIsStableAndSecretIsNotRecoverable(t *testing.T) {
	g, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !Equal(g.Hash, Hash(g.Secret)) {
		t.Fatal("hashing the same secret must produce the same hash")
	}
	if strings.Contains(string(g.Hash), strings.TrimPrefix(g.Secret, LivePrefix)) {
		t.Fatal("hash contains the secret")
	}
	other, _ := Generate()
	if Equal(g.Hash, other.Hash) {
		t.Fatal("different secrets produced the same hash")
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"no prefix":      "abcdef",
		"wrong prefix":   "aiem_test_aaaaaaaa",
		"bad alphabet":   LivePrefix + "!!!!",
		"too short":      LivePrefix + "aaaa",
		"prefix only":    LivePrefix,
		"embedded space": LivePrefix + "aaaa aaaa",
	}
	for name, in := range cases {
		if err := Parse(in); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}

func TestKeysAreCaseInsensitiveOnParse(t *testing.T) {
	g, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	upper := LivePrefix + strings.ToUpper(strings.TrimPrefix(g.Secret, LivePrefix))
	if err := Parse(upper); err != nil {
		t.Fatalf("an upper-cased key should still parse: %v", err)
	}
}

func TestLifetimeIsAlwaysBounded(t *testing.T) {
	if got := Lifetime(0); got != DefaultLifetime {
		t.Fatalf("unset lifetime must default, got %v", got)
	}
	if got := Lifetime(-time.Hour); got != DefaultLifetime {
		t.Fatalf("negative lifetime must default, got %v", got)
	}
	if got := Lifetime(10 * 365 * 24 * time.Hour); got != MaxLifetime {
		t.Fatalf("excessive lifetime must clamp, got %v", got)
	}
	if got := Lifetime(48 * time.Hour); got != 48*time.Hour {
		t.Fatalf("reasonable lifetime must pass through, got %v", got)
	}
}
