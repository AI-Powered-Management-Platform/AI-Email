package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/netguard"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
)

// runAddWebhook registers an endpoint and prints its signing secret once.
//
// The destination is validated here as well as at delivery time, so an
// operator learns immediately that an internal address will never be called
// rather than discovering it in a failed-delivery log.
func runAddWebhook(args []string) error {
	fs := flag.NewFlagSet("webhooks add", flag.ContinueOnError)
	target := fs.String("url", "", "https endpoint to receive events")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*target) == "" {
		return fmt.Errorf("-url is required")
	}
	if _, err := netguard.ValidateURL(*target); err != nil {
		return fmt.Errorf("that destination cannot be used: %w", err)
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

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generating endpoint secret: %w", err)
	}

	endpoint, err := db.CreateEndpoint(ctx, *target, secret)
	if err != nil {
		return err
	}

	fmt.Printf(`Webhook endpoint registered.

  id      %d
  url     %s
  secret  %s

Verify every delivery with this secret. An unsigned webhook is
indistinguishable from a forged one, and requests carry a signature over the
method, target, body digest, and creation time with a five minute window.

`, endpoint.ID, endpoint.URL, base64.StdEncoding.EncodeToString(secret))
	return nil
}
