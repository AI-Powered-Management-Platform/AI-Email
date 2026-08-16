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
	"syscall"
	"time"

	"github.com/AI-Powered-Management-Platform/AI-Email/internal/config"
	"github.com/AI-Powered-Management-Platform/AI-Email/internal/httpapi"
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
  aiemail serve     Serve the REST API
  aiemail worker    Run background delivery and event work
  aiemail version   Print the build version

Configuration comes from the environment; see docs/.
`)
}

func runServe() error {
	cfg, log, err := boot()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpapi.New(cfg, log, version).Handler(),
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
	_, log, err := boot()
	if err != nil {
		return err
	}
	log.Info("worker mode is not implemented yet")
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
