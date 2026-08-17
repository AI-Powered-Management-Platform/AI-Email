package dkim

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/mail"
)

// G9 — signing is a hot path: every message is signed before it leaves. The
// benchmark covers the whole per-message cost, including the unwrap that
// happens on each call because key material is never kept in memory (T10).
func BenchmarkSign(b *testing.B) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		b.Fatalf("master key: %v", err)
	}
	keeper, err := NewEnvelopeKeeper(master)
	if err != nil {
		b.Fatalf("keeper: %v", err)
	}
	pair, err := Generate(keeper, "s1")
	if err != nil {
		b.Fatalf("generate: %v", err)
	}
	msg, err := mail.Build(mail.Envelope{
		MessageID: "01BENCH@example.com",
		From:      "noreply@example.com",
		To:        []string{"user@example.org"},
		Subject:   "Benchmark message",
		HTML:      "<p>Hello</p>",
		Date:      time.Now(),
	})
	if err != nil {
		b.Fatalf("building message: %v", err)
	}

	signer := NewSigner(keeper)
	key := Key{Domain: "example.com", Selector: pair.Selector, Algorithm: pair.Algorithm, Wrapped: pair.WrappedSecret}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := signer.Sign(context.Background(), key, msg); err != nil {
			b.Fatal(err)
		}
	}
}
