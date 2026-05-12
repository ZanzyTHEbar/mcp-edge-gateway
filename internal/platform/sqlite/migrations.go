package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	dbmigrations "dragonserver/mcp-platform/db/migrations"

	"github.com/pressly/goose/v3"
)

func RunMigrations(ctx context.Context, db *sql.DB) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if db == nil {
		return fmt.Errorf("db is required")
	}
	migrationFS, err := fs.Sub(dbmigrations.Files, ".")
	if err != nil {
		return fmt.Errorf("open embedded sqlite migrations: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrationFS)
	if err != nil {
		return fmt.Errorf("create sqlite migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("run sqlite migrations: %w", err)
	}
	var busy, logFrames, checkpointedFrames int
	if err := db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointedFrames); err != nil {
		return fmt.Errorf("checkpoint sqlite database after migrations: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("checkpoint sqlite database after migrations was busy: log=%d checkpointed=%d", logFrames, checkpointedFrames)
	}
	return nil
}
