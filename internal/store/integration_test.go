package store_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

// These tests exercise real SQL. Claim semantics and transactional idempotency
// cannot be proven against a fake: the guarantees live in Postgres.
func testStore(t testing.TB) *store.Store {
	t.Helper()
	dsn := os.Getenv("AIEMAIL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AIEMAIL_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(s.Close)

	for _, table := range []string{"idempotency_records", "message_events", "messages", "api_keys", "domains"} {
		if _, err := s.Pool.Exec(ctx, "DELETE FROM "+table); err != nil {
			t.Fatalf("cleaning %s: %v", table, err)
		}
	}
	return s
}

func seed(t testing.TB, s *store.Store) (keyID, domainID int64) {
	t.Helper()
	ctx := context.Background()

	key, err := s.CreateAPIKey(ctx, store.NewAPIKey{
		Name:       "test",
		Prefix:     "aiem_live_test…",
		SecretHash: []byte("0123456789abcdef0123456789abcdef"),
		Scopes:     []string{"emails:send"},
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO domains (name, verification_token, status, verified_at)
		 VALUES ('example.com', 'token', 'verified', now()) RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("create domain: %v", err)
	}
	return key.ID, domainID
}

func newMessage(id string, keyID, domainID int64, idempotencyKey string, hash []byte) store.NewMessage {
	return store.NewMessage{
		ID:             id,
		APIKeyID:       keyID,
		DomainID:       domainID,
		FromAddress:    "noreply@example.com",
		Recipients:     []string{"user@example.org"},
		Subject:        "subject",
		BodyText:       "body",
		Headers:        []byte(`{}`),
		Tags:           []byte(`{}`),
		IdempotencyKey: idempotencyKey,
		RequestHash:    hash,
	}
}

func TestIdempotentEnqueueUnderConcurrency(t *testing.T) {
	s := testStore(t)
	keyID, domainID := seed(t, s)
	ctx := context.Background()
	hash := []byte("same-request-hash-value-00000000")

	const racers = 8
	var wg sync.WaitGroup
	ids := make([]string, racers)
	errs := make([]error, racers)

	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg, _, err := s.EnqueueMessage(ctx, newMessage(ulidLike(i), keyID, domainID, "shared-key", hash))
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = msg.ID
		}()
	}
	wg.Wait()

	var accepted int
	for i := range racers {
		if errs[i] == nil && ids[i] != "" {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatalf("no request succeeded: %v", errs)
	}

	var count int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages`).Scan(&count); err != nil {
		t.Fatalf("counting messages: %v", err)
	}
	if count != 1 {
		t.Fatalf("one idempotency key must yield exactly one message, got %d", count)
	}
}

func TestIdempotencyMismatchIsRejected(t *testing.T) {
	s := testStore(t)
	keyID, domainID := seed(t, s)
	ctx := context.Background()

	if _, _, err := s.EnqueueMessage(ctx, newMessage("01AAAA", keyID, domainID, "k1", []byte("hash-one-000000000000000000000000"))); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	_, _, err := s.EnqueueMessage(ctx, newMessage("01BBBB", keyID, domainID, "k1", []byte("hash-two-000000000000000000000000")))
	if err != store.ErrIdempotencyMismatch {
		t.Fatalf("expected a mismatch error, got %v", err)
	}
}

func TestClaimGivesEachMessageToOneWorkerOnly(t *testing.T) {
	s := testStore(t)
	keyID, domainID := seed(t, s)
	ctx := context.Background()

	const total = 20
	for i := range total {
		if _, _, err := s.EnqueueMessage(ctx, newMessage(ulidLike(i), keyID, domainID, "", nil)); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	const workers = 4
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]int{}

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claimed, err := s.ClaimMessages(ctx, 10, time.Minute)
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, c := range claimed {
				seen[c.ID]++
			}
		}()
	}
	wg.Wait()

	for id, n := range seen {
		if n != 1 {
			t.Fatalf("message %s was claimed %d times; concurrent workers must not double-send", id, n)
		}
	}
	if len(seen) != total {
		t.Fatalf("expected all %d messages claimed, got %d", total, len(seen))
	}
}

func TestExpiredLockMakesMessageClaimableAgain(t *testing.T) {
	s := testStore(t)
	keyID, domainID := seed(t, s)
	ctx := context.Background()

	if _, _, err := s.EnqueueMessage(ctx, newMessage("01CRASH", keyID, domainID, "", nil)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Claim it, then simulate the worker dying: the row stays 'sending' with a
	// lock that lapses.
	first, err := s.ClaimMessages(ctx, 1, time.Hour)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim: %v (%d rows)", err, len(first))
	}
	if _, err := s.Pool.Exec(ctx,
		`UPDATE messages SET status='deferred', locked_until = now() - interval '1 minute' WHERE id=$1`, "01CRASH"); err != nil {
		t.Fatalf("expiring lock: %v", err)
	}

	again, err := s.ClaimMessages(ctx, 1, time.Minute)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(again) != 1 {
		t.Fatal("a message whose worker died must become claimable again")
	}
	if again[0].Attempts != 2 {
		t.Fatalf("each claim must count as an attempt, got %d", again[0].Attempts)
	}
}

func TestLifecycleRecordsEvents(t *testing.T) {
	s := testStore(t)
	keyID, domainID := seed(t, s)
	ctx := context.Background()

	if _, _, err := s.EnqueueMessage(ctx, newMessage("01LIFE", keyID, domainID, "", nil)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := s.ClaimMessages(ctx, 1, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := s.MarkDeferred(ctx, "01LIFE", time.Now().Add(time.Minute), "greylisted by destination"); err != nil {
		t.Fatalf("defer: %v", err)
	}
	if err := s.MarkSent(ctx, "01LIFE"); err != nil {
		t.Fatalf("mark sent: %v", err)
	}

	events, err := s.EventsForMessage(ctx, "01LIFE")
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected deferred then sent, got %d events", len(events))
	}
	if events[0].Type != "email.deferred" || events[1].Type != "email.sent" {
		t.Fatalf("unexpected event order: %+v", events)
	}
	if events[0].Detail != "greylisted by destination" {
		t.Fatalf("defer reason should be recorded, got %q", events[0].Detail)
	}

	n, err := s.SentInLastHour(ctx)
	if err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 1 {
		t.Fatalf("the ceiling counter must see the dispatch, got %d", n)
	}
}

func ulidLike(i int) string {
	const digits = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	return "01TEST" + string(digits[i%len(digits)]) + string(digits[(i/32)%len(digits)])
}
