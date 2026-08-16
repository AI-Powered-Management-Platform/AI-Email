package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/keys"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

// runCreateKey issues the first credential. Bootstrapping over HTTP would need
// a credential to create a credential, so this lives on the command line where
// filesystem access is already the trust boundary.
func runCreateKey(args []string) error {
	fs := flag.NewFlagSet("keys create", flag.ContinueOnError)
	name := fs.String("name", "", "human-readable label for the key")
	scopes := fs.String("scopes", "emails:send,emails:read", "comma-separated scopes")
	quota := fs.Int("quota", 0, "maximum messages per hour, 0 for the deployment default")
	days := fs.Int("days", 90, "lifetime in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("-name is required")
	}

	cfg, _, err := boot()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := store.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	generated, err := keys.Generate()
	if err != nil {
		return err
	}

	lifetime := keys.Lifetime(time.Duration(*days) * 24 * time.Hour)
	created, err := db.CreateAPIKey(ctx, store.NewAPIKey{
		Name:         *name,
		Prefix:       generated.Prefix,
		SecretHash:   generated.Hash,
		Scopes:       splitScopes(*scopes),
		QuotaPerHour: *quota,
		ExpiresAt:    time.Now().Add(lifetime),
	})
	if err != nil {
		return err
	}

	fmt.Printf(`Key created. This is the only time the secret is shown.

  id      %d
  name    %s
  scopes  %s
  expires %s

  %s

`, created.ID, created.Name, strings.Join(created.Scopes, ", "),
		created.ExpiresAt.UTC().Format(time.RFC3339), generated.Secret)
	return nil
}

func runAddDomain(args []string) error {
	fs := flag.NewFlagSet("domains add", flag.ContinueOnError)
	name := fs.String("name", "", "domain to send from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("-name is required")
	}

	cfg, _, err := boot()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := store.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return err
	}
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	token, err := verificationToken()
	if err != nil {
		return err
	}

	domain := strings.ToLower(strings.TrimSpace(*name))
	const q = `INSERT INTO domains (name, verification_token) VALUES ($1, $2)
	           ON CONFLICT (name) DO UPDATE SET verification_token = EXCLUDED.verification_token
	           RETURNING id, verification_token`
	var id int64
	var stored string
	if err := db.Pool.QueryRow(ctx, q, domain, token).Scan(&id, &stored); err != nil {
		return err
	}

	fmt.Printf(`Domain %s registered, awaiting DNS proof.

Publish this record, then verification will pass:

  _aiemail.%s   TXT   "%s"

`, domain, domain, stored)
	return nil
}

func splitScopes(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func verificationToken() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating verification token: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return "aiemail-verify=" + strings.ToLower(enc.EncodeToString(b)), nil
}
