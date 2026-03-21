package edge

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp-edge",
		Short: "Run the DragonServer MCP shared edge",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := LoadConfig()
			if err := cfg.Validate(); err != nil {
				return err
			}
			logger := buildLogger(cfg)
			server, err := NewServer(cfg, logger, nil)
			if err != nil {
				return err
			}
			defer func() {
				_ = server.Close()
			}()
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			return server.ListenAndServe(ctx, cfg)
		},
	}
}

func buildLogger(cfg Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(level)
	return logger.Level(level).With().Timestamp().Logger()
}
