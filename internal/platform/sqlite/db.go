package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/tursodatabase/go-libsql"
)

const (
	configureTimeout = 5 * time.Second
	maxOpenConns     = 1
	maxIdleConns     = 1
)

func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		dsn = "file:data/mcp-platform.db"
	}
	if strings.HasPrefix(dsn, "file:") {
		path := strings.TrimPrefix(dsn, "file:")
		if path != "" && path != ":memory:" {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return nil, fmt.Errorf("create sqlite database directory: %w", err)
			}
		}
	}
	db, err := sql.Open("libsql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	if err := configure(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

type pragmaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func configure(ctx context.Context, db *sql.DB) error {
	ctx, cancel := context.WithTimeout(ctx, configureTimeout)
	defer cancel()
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	if err := applyDatabasePragmas(ctx, db); err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open sqlite configuration connection: %w", err)
	}
	defer conn.Close()
	return applyConnectionPragmas(ctx, conn)
}

func applyDatabasePragmas(ctx context.Context, db *sql.DB) error {
	if err := applyBusyTimeout(ctx, db); err != nil {
		return err
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&journalMode); err != nil {
		return fmt.Errorf("set sqlite journal_mode WAL: %w", err)
	}
	if strings.ToLower(journalMode) != "wal" && strings.ToLower(journalMode) != "memory" {
		return fmt.Errorf("set sqlite journal_mode WAL returned %q", journalMode)
	}
	return nil
}

func applyConnectionPragmas(ctx context.Context, execer pragmaExecer) error {
	if _, err := execer.ExecContext(ctx, "PRAGMA synchronous = FULL"); err != nil {
		return fmt.Errorf("set sqlite synchronous FULL: %w", err)
	}
	if _, err := execer.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("set sqlite foreign_keys ON: %w", err)
	}
	var foreignKeys int
	if err := execer.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fmt.Errorf("read sqlite foreign_keys: %w", err)
	}
	if foreignKeys != 1 {
		return fmt.Errorf("sqlite foreign_keys = %d, want 1", foreignKeys)
	}
	return applyBusyTimeout(ctx, execer)
}

func applyBusyTimeout(ctx context.Context, execer pragmaExecer) error {
	var busyTimeout int
	if err := execer.QueryRowContext(ctx, "PRAGMA busy_timeout = 5000").Scan(&busyTimeout); err != nil {
		return fmt.Errorf("set sqlite busy_timeout: %w", err)
	}
	if busyTimeout != 5000 {
		return fmt.Errorf("sqlite busy_timeout = %d, want 5000", busyTimeout)
	}
	return nil
}
