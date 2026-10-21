package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dragonserver/mcp-platform/internal/credentialbridge"
)

func main() {
	if err := credentialbridge.DisableCoreDumps(); err != nil {
		fmt.Fprintln(os.Stderr, "cannot disable credential process core dumps")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cmd := credentialbridge.NewCommand()
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
