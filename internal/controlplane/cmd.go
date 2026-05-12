package controlplane

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dragonserver/mcp-platform/internal/contracts"
	"dragonserver/mcp-platform/internal/selfcheck"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
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

	cmd.AddCommand(newHealthcheckCommand())
	return cmd
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

func newHealthcheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck",
		Short: "Probe the local control-plane readiness endpoint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return selfcheck.ProbeHTTP(
				os.Getenv(contracts.EnvControlPlaneHTTPBindAddr),
				":8081",
				"/health/ready",
				5*time.Second,
			)
		},
	}
}
