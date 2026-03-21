package main

import (
	"os"

	"dragonserver/mcp-platform/internal/edge"
)

func main() {
	if err := edge.NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
