//go:build integration

package edge

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/credentialbridge"

	"github.com/stretchr/testify/require"
)

// A complete boundary scenario: standard device polling against the real Edge,
// browser consent, private persistence, refresh, and bidirectional stdio/HTTP MCP.
func TestCredentialBridgeDeviceLoginAndStdio(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	notificationSent := make(chan struct{})
	var streamConnections atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet {
			if r.Header.Get("Mcp-Session-Id") != "bridge-session" || r.Header.Get("MCP-Protocol-Version") != "2025-11-25" {
				http.Error(w, "missing session headers", 400)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			connectionNumber := streamConnections.Add(1)
			if connectionNumber == 1 {
				// A quiet stream is primed, then its HTTP connection is cut like
				// an idle proxy timeout. The bridge must retain the session/cursor.
				fmt.Fprint(w, "id: idle-cursor\ndata:\n\n")
				w.(http.Flusher).Flush()
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("cut idle stream: %v", err)
					return
				}
				connection.Close()
				return
			}
			if connectionNumber == 2 {
				// Some gateways report an idle stream failure as HTTP 500.
				http.Error(w, "temporary notification stream failure", http.StatusInternalServerError)
				return
			}
			if r.Header.Get("Last-Event-ID") != "idle-cursor" {
				http.Error(w, "missing stream cursor", 400)
				return
			}
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
			w.(http.Flusher).Flush()
			close(notificationSent)
			<-r.Context().Done()
			return
		}
		var message struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&message) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		if message.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if message.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "bridge-session")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{ "jsonrpc": "2.0", "id": %s, "result": { "protocolVersion": "2025-11-25", "capabilities": {"tools":{}}, "serverInfo": {"name":"acceptance","version":"1"} } }`, message.ID)
			return
		}
		if r.Header.Get("Mcp-Session-Id") != "bridge-session" {
			http.Error(w, "missing session", 400)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "id: priming-cursor\ndata:\n\n")
		fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"through authenticated edge\"}]}}\n\n", message.ID)
	}))
	defer upstream.Close()
	web := httptest.NewUnstartedServer(nil)
	cfg := testEdgeConfig()
	cfg.PublicBaseURL = "http://" + web.Listener.Addr().String()
	cfg.DCREnabled = true
	edge := newTestEdgeServerWithConfig(t, cfg, urlResolver{targets: map[string]string{"example-a": upstream.URL}})
	defer edge.Close()
	pending := make(chan struct{})
	var firstPoll sync.Once
	var refreshes atomic.Int32
	handler := edge.Handler()
	web.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			r.ParseForm()
			if r.Form.Get("grant_type") == "refresh_token" {
				refreshes.Add(1)
			}
			if r.Form.Get("grant_type") == oauthGrantDeviceCode {
				defer firstPoll.Do(func() { close(pending) })
			}
		}
		handler.ServeHTTP(w, r)
	})
	web.Start()
	defer web.Close()
	resource := web.URL + "/example-a/mcp"
	directory := filepath.Join(t.TempDir(), "credentials")
	client, err := credentialbridge.New(resource, directory)
	require.NoError(t, err)
	t.Cleanup(func() {
		command := credentialbridge.NewCommand()
		command.SetArgs([]string{"logout", "--url", resource, "--state-dir", directory})
		command.SetErr(io.Discard)
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		require.NoError(t, command.ExecuteContext(cleanup))
	})
	loginReader, loginWriter := io.Pipe()
	defer loginReader.Close()
	defer loginWriter.Close()
	loginDone := make(chan error, 1)
	go func() { loginDone <- client.Login(ctx, "", loginWriter); loginWriter.Close() }()
	lines := bufio.NewReader(loginReader)
	line, err := lines.ReadString('\n')
	require.NoError(t, err)
	verification := strings.TrimSpace(strings.TrimPrefix(line, "Open on any device: "))
	_, err = lines.ReadString('\n') // user code
	require.NoError(t, err)
	_, err = lines.ReadString('\n') // waiting
	require.NoError(t, err)
	select {
	case <-pending:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	browser := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	response, err := browser.Get(verification)
	require.NoError(t, err)
	page, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	codeURL, err := url.Parse(verification)
	require.NoError(t, err)
	response, err = browser.PostForm(web.URL+"/oauth/device", url.Values{
		"user_code": {codeURL.Query().Get("user_code")}, "csrf_token": {extractDeviceCSRFToken(t, string(page))}, "action": {"approve"},
	})
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	// Drain the final login message so the explicit login command can finish.
	_, err = io.ReadAll(lines)
	require.NoError(t, err)
	require.NoError(t, <-loginDone)
	files, err := filepath.Glob(filepath.Join(directory, "*.json"))
	require.NoError(t, err)
	require.Empty(t, files, "credentials must not be stored in filesystem JSON files")
	key := sha256.Sum256([]byte(resource))
	account := hex.EncodeToString(key[:])
	info, err := os.Stat(filepath.Join(directory, account+".lock"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.Zero(t, info.Size(), "the refresh lock must contain no credential data")
	// Exercise the real Secret Service boundary, not a mock keystore. Simulate
	// access expiry by updating the encrypted item through libsecret in memory.
	body, err := exec.CommandContext(ctx, "secret-tool", "lookup", "service", "mcp-edge-credential-bridge", "resource", account).Output()
	require.NoError(t, err)
	var stored map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &stored))
	var token map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(stored["token"], &token))
	token["expiry"], err = json.Marshal(time.Now().Add(-time.Minute))
	require.NoError(t, err)
	stored["token"], err = json.Marshal(token)
	require.NoError(t, err)
	body, err = json.Marshal(stored)
	require.NoError(t, err)
	update := exec.CommandContext(ctx, "secret-tool", "store", "--label=MCP Edge OAuth credential", "--collection=default", "service", "mcp-edge-credential-bridge", "resource", account)
	update.Stdin = strings.NewReader(string(body))
	_, err = update.Output()
	require.NoError(t, err)
	input, send := io.Pipe()
	output, receive := io.Pipe()
	defer send.Close()
	defer output.Close()
	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- client.Serve(ctx, input, receive) }()
	stdio := bufio.NewReader(output)
	_, err = io.WriteString(send, `{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"acceptance","version":"1"}}}`+"\n")
	require.NoError(t, err)
	line, err = stdio.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, line, `"id":"init"`)
	_, err = io.WriteString(send, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	require.NoError(t, err)
	line, err = stdio.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, line, "notifications/tools/list_changed")
	require.Equal(t, int32(3), streamConnections.Load(), "recover from an idle disconnect and HTTP 500 without exiting the stdio session")
	_, err = io.WriteString(send, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`+"\n")
	require.NoError(t, err)
	line, err = stdio.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, line, "through authenticated edge")
	require.Equal(t, int32(1), refreshes.Load(), "persist the rotated token rather than refreshing on every request")
	send.Close()
	require.NoError(t, <-bridgeDone)
}
