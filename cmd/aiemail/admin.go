package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/dkim"
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

	if len(cfg.DKIMMasterKey) == 0 {
		return errors.New("AIEMAIL_DKIM_MASTER_KEY is required to generate a signing key; generate one with: aiemail keygen")
	}
	keeper, err := dkim.NewEnvelopeKeeper(cfg.DKIMMasterKey)
	if err != nil {
		return err
	}

	selector := time.Now().UTC().Format("200601")
	pair, err := dkim.Generate(keeper, selector)
	if err != nil {
		return err
	}
	if _, err := db.CreateSigningKey(ctx, id, pair.Selector, pair.Algorithm, pair.WrappedSecret, pair.PublicRecord); err != nil {
		return err
	}

	fmt.Printf(`Domain %s registered, awaiting DNS proof.

Publish these records:

  _aiemail.%s   TXT   "%s"

  %s   TXT   "%s"

  %s   TXT   "v=spf1 include:%s ~all"

  _dmarc.%s   TXT   "v=DMARC1; p=none; rua=mailto:dmarc@%s"

Start DMARC at p=none, read the reports, and move to quarantine then reject
once you can see that legitimate mail passes.

`, domain, domain, stored,
		dkim.DNSRecordName(pair.Selector, domain), pair.PublicRecord,
		domain, domain,
		domain, domain)
	return nil
}

// runKeygen prints a master key. It never writes one to disk: where the secret
// lives is the operator's decision, and a file we created would be one more
// copy nobody asked for.
func runKeygen() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generating master key: %w", err)
	}
	fmt.Printf(`AIEMAIL_DKIM_MASTER_KEY=%s

Store this in your secret manager, not in a file beside the database. Losing
it means every signing key must be regenerated and every DKIM record
republished; leaking it means an attacker can sign mail as your domains.

`, base64.StdEncoding.EncodeToString(key))
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
