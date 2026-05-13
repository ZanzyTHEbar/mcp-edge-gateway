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
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, migrationFS, goose.WithAllowOutofOrder(true))
	if err != nil {
		return fmt.Errorf("create sqlite migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("run sqlite migrations: %w", err)
	}
	var busy, logFrames, checkpointedFrames int
	// A checkpoint is best-effort here: migrations are complete once goose commits.
	// Edge/control-plane split deployments may legitimately keep another SQLite
	// connection open, so checkpoint errors must not make startup fail.
	_ = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &logFrames, &checkpointedFrames)
	_ = busy
	_ = logFrames
	_ = checkpointedFrames
	return nil
}
