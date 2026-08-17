// Command aiemail is the AI-Email server.
//
// One binary serves every run mode so a self-hosted deployment starts a single
// process. Subcommands select the mode.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/config"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/delivery"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/dnsverify"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/httpapi"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/store"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/webhook"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/worker"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "aiemail: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	mode := "serve"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	switch mode {
	case "version":
		fmt.Println(version)
		return nil
	case "serve":
		return runServe()
	case "worker":
		return runWorker()
	case "keys":
		if len(os.Args) > 2 && os.Args[2] == "create" {
			return runCreateKey(os.Args[3:])
		}
		return fmt.Errorf("usage: aiemail keys create -name NAME")
	case "domains":
		if len(os.Args) > 2 && os.Args[2] == "add" {
			return runAddDomain(os.Args[3:])
		}
		return fmt.Errorf("usage: aiemail domains add -name DOMAIN")
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", mode)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `aiemail — AI-Email server

Usage:
  aiemail serve          Serve the REST API
  aiemail worker         Run background delivery and event work
  aiemail keys create    Issue an API key (shown once)
  aiemail domains add    Register a sending domain
  aiemail version        Print the build version

Configuration comes from the environment; see docs/.
`)
}

func runServe() error {
	cfg, log, err := boot()
	if err != nil {
		return err
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()

	if err := store.Migrate(startupCtx, cfg.DatabaseURL); err != nil {
		return err
	}

	db, err := store.Open(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	schema, err := store.SchemaVersion(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	log.Info("schema ready", "version", schema)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpapi.New(cfg, log, db, db, db, version).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "env", cfg.Env, "send_enabled", cfg.SendEnabled)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server failed: %w", err)
	case <-ctx.Done():
		log.Info("shutting down", "grace", cfg.ShutdownGrace.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	log.Info("stopped")
	return nil
}

func runWorker() error {
	cfg, log, err := boot()
	if err != nil {
		return err
	}
	if !cfg.SendEnabled {
		return errors.New("sending is disabled on this deployment; set AIEMAIL_SEND_ENABLED=true to run the worker")
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()

	if err := store.Migrate(startupCtx, cfg.DatabaseURL); err != nil {
		return err
	}
	db, err := store.Open(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Three independent loops. A stuck webhook endpoint must not hold up mail,
	// and a DNS outage must not hold up either.
	var wg sync.WaitGroup
	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil {
				log.Error(name+" stopped with an error", "error", err)
			}
		}()
	}

	run("delivery", worker.New(db, delivery.NewEngine(cfg.EngineURL), log, cfg.MaxSendPerHour).Run)
	run("webhooks", worker.NewDispatcher(db, webhook.NewSender(20*time.Second), log).Run)
	run("domains", worker.NewDomainChecker(db, dnsverify.New(nil, 10*time.Second), log).Run)

	wg.Wait()
	return nil
}

func boot() (*config.Config, *slog.Logger, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	log := newLogger(cfg.LogLevel)
	return cfg, log, nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
