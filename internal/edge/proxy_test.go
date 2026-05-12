package edge

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRewriteProxyPathTranslatesActualBudgetPath(t *testing.T) {
	t.Parallel()

	require.Equal(t, "/http", rewriteProxyPath("/actualbudget/mcp", "/actualbudget/mcp", "/http"))
	require.Equal(t, "/http/tools/list", rewriteProxyPath("/actualbudget/mcp/tools/list", "/actualbudget/mcp", "/http"))
}

func TestSSEToStreamableHTTPBridgeDoesNotWaitForNotificationResponse(t *testing.T) {
	t.Parallel()

	requestBody := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			require.True(t, ok)
			_, _ = io.WriteString(w, "event: endpoint\n")
			_, _ = io.WriteString(w, "data: /message?sessionid=test-session\n\n")
			flusher.Flush()
			<-r.Context().Done()
		case "/message":
			require.Equal(t, "test-session", r.URL.Query().Get("sessionid"))
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.JSONEq(t, string(requestBody), string(body))
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	handler := NewSSEToStreamableHTTPBridge(targetURL, "/memory/mcp", "/sse", false, zerolog.New(io.Discard))
	req := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader(requestBody))
	res := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(res, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge waited for an SSE response to a JSON-RPC notification")
	}
	require.Equal(t, http.StatusAccepted, res.Code)
	require.Empty(t, res.Body.String())
}

func TestSSEToStreamableHTTPBridgeSuppressesEntireEndpointEvent(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/sse", r.URL.Path)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)
		_, _ = io.WriteString(w, "event: endpoint\n")
		_, _ = io.WriteString(w, "data: /message?sessionid=test-session\n\n")
		_, _ = io.WriteString(w, "event: message\n")
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	handler := NewSSEToStreamableHTTPBridge(targetURL, "/memory/mcp", "/sse", false, zerolog.New(io.Discard))
	req := httptest.NewRequest(http.MethodGet, "/memory/mcp", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NotContains(t, res.Body.String(), "endpoint")
	require.NotContains(t, res.Body.String(), "/message?sessionid=test-session")
	require.Contains(t, res.Body.String(), "notifications/tools/list_changed")
}

func TestSSEToStreamableHTTPBridgeForwardsPostThroughUpstreamEndpoint(t *testing.T) {
	t.Parallel()

	requestBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			require.True(t, ok)
			_, _ = io.WriteString(w, "event: endpoint\n")
			_, _ = io.WriteString(w, "data: /message?sessionid=test-session\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n")
			flusher.Flush()
		case "/message":
			require.Equal(t, "test-session", r.URL.Query().Get("sessionid"))
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.JSONEq(t, string(requestBody), string(body))
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	handler := NewSSEToStreamableHTTPBridge(
		targetURL,
		"/memory/mcp",
		"/sse",
		false,
		zerolog.New(io.Discard),
	)

	req := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader(requestBody))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(t, "application/json", res.Header().Get("Content-Type"))
	require.JSONEq(t, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, res.Body.String())
}
