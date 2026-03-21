package main

import (
	"os"

	"dragonserver/mcp-platform/internal/controlplane"
)

func main() {
	if err := controlplane.NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
