package selfcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func ProbeHTTP(bindAddr, defaultBindAddr, path string, timeout time.Duration) error {
	targetURL, err := ResolveHTTPURL(bindAddr, defaultBindAddr, path)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(targetURL)
	if err != nil {
		return fmt.Errorf("probe %s: %w", targetURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read %s response: %w", targetURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"probe %s returned status %d: %s",
			targetURL,
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 {
		return nil
	}

	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(trimmedBody, &payload); err != nil {
		return nil
	}
	if payload.Status == "" || payload.Status == "ready" || payload.Status == "live" {
		return nil
	}

	return fmt.Errorf("probe %s reported status %q", targetURL, payload.Status)
}

func ResolveHTTPURL(bindAddr, defaultBindAddr, path string) (string, error) {
	resolvedBindAddr := strings.TrimSpace(bindAddr)
	if resolvedBindAddr == "" {
		resolvedBindAddr = strings.TrimSpace(defaultBindAddr)
	}
	if resolvedBindAddr == "" {
		return "", fmt.Errorf("bind address is required")
	}

	host, port, err := splitBindAddr(resolvedBindAddr)
	if err != nil {
		return "", fmt.Errorf("parse bind address %q: %w", resolvedBindAddr, err)
	}
	if port == "" {
		return "", fmt.Errorf("parse bind address %q: missing port", resolvedBindAddr)
	}

	probePath := path
	if probePath == "" {
		probePath = "/"
	}
	if !strings.HasPrefix(probePath, "/") {
		probePath = "/" + probePath
	}

	return "http://" + net.JoinHostPort(normalizeProbeHost(host), port) + probePath, nil
}

func splitBindAddr(bindAddr string) (string, string, error) {
	if strings.HasPrefix(bindAddr, ":") {
		return "", strings.TrimPrefix(bindAddr, ":"), nil
	}

	if isNumeric(bindAddr) {
		return "", bindAddr, nil
	}

	host, port, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

func normalizeProbeHost(host string) string {
	switch strings.TrimSpace(host) {
	case "", "0.0.0.0", "::":
		return "127.0.0.1"
	default:
		return host
	}
}

func isNumeric(value string) bool {
	if value == "" {
		return false
	}

	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}
