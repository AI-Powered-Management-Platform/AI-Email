// Package store owns the Postgres connection and schema migrations.
//
// Queue truth lives in Postgres. A message counts as accepted only once it is
// committed here, which is what makes delivery survive a crash.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver, used for migrations
	"github.com/pressly/goose/v3"

	"github.com/AI-Powered-Management-Platform/AI-Email/migrations"
)

type Store struct {
	Pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing database url: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database unreachable: %w", err)
	}

	return &Store{Pool: pool}, nil
}

func (s *Store) Close() {
	if s.Pool != nil {
		s.Pool.Close()
	}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.Pool.Ping(ctx)
}

// Migrate applies pending migrations at startup so a self-hosted deployment
// never needs a separate migration step.
func Migrate(ctx context.Context, dsn string) error {
	db, err := openSQL(dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := prepareGoose(); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}

// SchemaVersion reports the applied migration version.
func SchemaVersion(ctx context.Context, dsn string) (int64, error) {
	db, err := openSQL(dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	if err := prepareGoose(); err != nil {
		return 0, err
	}
	return goose.GetDBVersionContext(ctx, db)
}

func openSQL(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	return db, nil
}

func prepareGoose() error {
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting migration dialect: %w", err)
	}
	return nil
}
