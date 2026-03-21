package controlplane

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp-control-plane",
		Short: "Run the DragonServer MCP control plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig()
			if err != nil {
				return err
			}

			logger := buildLogger(cfg.LogLevel)
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			app, err := NewApp(ctx, cfg, logger)
			if err != nil {
				return fmt.Errorf("build control-plane app: %w", err)
			}
			defer app.Close()

			return app.Run(ctx)
		},
	}
}

func buildLogger(logLevel string) zerolog.Logger {
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(level)
	return logger.Level(level).With().Timestamp().Logger()
}
