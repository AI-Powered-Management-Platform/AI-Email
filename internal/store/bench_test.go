package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// G9 — enqueue and claim run on every message and every delivery attempt.
// Like the integration tests, these need real Postgres and skip when
// AIEMAIL_TEST_DATABASE_URL is not set.

func BenchmarkEnqueueMessage(b *testing.B) {
	s := testStore(b)
	keyID, domainID := seed(b, s)
	ctx := context.Background()
	hash := []byte("0123456789abcdef0123456789abcdef")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("bench-enq-%d", i)
		if _, _, err := s.EnqueueMessage(ctx, newMessage(id, keyID, domainID, id, hash)); err != nil {
			b.Fatalf("enqueue: %v", err)
		}
	}
}

func BenchmarkClaimMessages(b *testing.B) {
	s := testStore(b)
	keyID, domainID := seed(b, s)
	ctx := context.Background()
	hash := []byte("0123456789abcdef0123456789abcdef")

	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("bench-claim-%d", i)
		if _, _, err := s.EnqueueMessage(ctx, newMessage(id, keyID, domainID, id, hash)); err != nil {
			b.Fatalf("enqueue: %v", err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	claimed := 0
	for claimed < b.N {
		batch, err := s.ClaimMessages(ctx, 10, time.Minute)
		if err != nil {
			b.Fatalf("claim: %v", err)
		}
		if len(batch) == 0 {
			b.Fatalf("queue ran dry after %d of %d", claimed, b.N)
		}
		claimed += len(batch)
	}
}
