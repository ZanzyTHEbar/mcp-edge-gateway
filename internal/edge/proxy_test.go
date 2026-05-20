package edge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

func TestStreamSafeReverseProxyForwardsMCPTransportHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/http", r.URL.Path)
		require.Empty(t, r.Header.Get("Authorization"))
		require.Equal(t, "2025-11-25", r.Header.Get("MCP-Protocol-Version"))
		require.Equal(t, "session-123", r.Header.Get("MCP-Session-Id"))
		require.Equal(t, "event-456", r.Header.Get("Last-Event-ID"))
		require.Equal(t, "application/json, text/event-stream", r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	defer upstream.CloseClientConnections()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	handler := NewStreamSafeReverseProxy(targetURL, "/actualbudget/mcp", "/http", false, zerolog.New(io.Discard))
	req := httptest.NewRequest(http.MethodPost, "/actualbudget/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)))
	req.Header.Set("Authorization", "Bearer local-token")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("MCP-Session-Id", "session-123")
	req.Header.Set("Last-Event-ID", "event-456")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"ok":true}`, res.Body.String())
}

func TestStreamSafeReverseProxyReplacesSpoofedIdentityHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "trusted-sub", r.Header.Get(subjectHeaderSub))
		require.Equal(t, "trusted-signature", r.Header.Get(identityHeaderSignature))
		require.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	defer upstream.CloseClientConnections()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	identityHeaders := http.Header{}
	identityHeaders.Set(subjectHeaderSub, "trusted-sub")
	identityHeaders.Set(identityHeaderSignature, "trusted-signature")

	handler := NewStreamSafeReverseProxy(targetURL, "/penpot/mcp", "/mcp", false, zerolog.New(io.Discard))
	req := httptest.NewRequest(http.MethodPost, "/penpot/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}`)))
	req.Header.Set("Authorization", "Bearer local-token")
	req.Header.Set(subjectHeaderSub, "spoofed-sub")
	req.Header.Set(identityHeaderSignature, "spoofed-signature")
	req = req.WithContext(withUpstreamIdentityHeaders(req.Context(), identityHeaders))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
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
	defer upstream.CloseClientConnections()

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
	defer upstream.CloseClientConnections()

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
	defer upstream.CloseClientConnections()

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

func TestSSEToStreamableHTTPBridgeReusesUpstreamSession(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	nextSession := 0
	initialized := make(map[string]bool)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			mu.Lock()
			nextSession++
			sessionID := fmt.Sprintf("test-session-%d", nextSession)
			mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, ok := w.(http.Flusher)
			require.True(t, ok)
			_, _ = io.WriteString(w, "event: endpoint\n")
			_, _ = io.WriteString(w, "data: /message?sessionid="+sessionID+"\n\n")
			flusher.Flush()
			<-r.Context().Done()
		case "/message":
			sessionID := r.URL.Query().Get("sessionid")
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(http.StatusAccepted)
			if strings.Contains(string(body), `"method":"initialize"`) {
				mu.Lock()
				initialized[sessionID] = true
				mu.Unlock()
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2024-11-05"}}`)
				return
			}
			mu.Lock()
			ok := initialized[sessionID]
			mu.Unlock()
			if ok {
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
				return
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"not initialized"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	defer upstream.CloseClientConnections()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	handler := NewSSEToStreamableHTTPBridge(targetURL, "/memory/mcp", "/sse", false, zerolog.New(io.Discard))

	initReq := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":0,"method":"initialize"}`)))
	initRes := httptest.NewRecorder()
	handler.ServeHTTP(initRes, initReq)
	require.Equal(t, http.StatusAccepted, initRes.Code)
	sessionID := initRes.Header().Get("MCP-Session-Id")
	require.NotEmpty(t, sessionID)

	toolsReq := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	toolsReq.Header.Set("MCP-Session-Id", sessionID)
	toolsRes := httptest.NewRecorder()
	handler.ServeHTTP(toolsRes, toolsReq)
	require.Equal(t, http.StatusAccepted, toolsRes.Code)
	require.Contains(t, toolsRes.Body.String(), `"result"`)
	require.NotContains(t, toolsRes.Body.String(), "not initialized")
}

func TestSSEToStreamableHTTPBridgeRejectsBatchRequests(t *testing.T) {
	t.Parallel()

	targetURL, err := url.Parse("http://127.0.0.1:1")
	require.NoError(t, err)
	handler := NewSSEToStreamableHTTPBridge(targetURL, "/memory/mcp", "/sse", false, zerolog.New(io.Discard))

	req := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader([]byte(`[ {"jsonrpc":"2.0","id":1,"method":"tools/list"} ]`)))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "unsupported_batch")
}

func TestSSEToStreamableHTTPBridgeRejectsUnknownSession(t *testing.T) {
	t.Parallel()

	targetURL, err := url.Parse("http://127.0.0.1:1")
	require.NoError(t, err)
	handler := NewSSEToStreamableHTTPBridge(targetURL, "/memory/mcp", "/sse", false, zerolog.New(io.Discard))

	req := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	req.Header.Set("MCP-Session-Id", "missing-session")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusNotFound, res.Code)
	require.Contains(t, res.Body.String(), "session_not_found")
}

func TestSSEToStreamableHTTPBridgeDeletesSession(t *testing.T) {
	t.Parallel()

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
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	defer upstream.CloseClientConnections()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	handler := NewSSEToStreamableHTTPBridge(targetURL, "/memory/mcp", "/sse", false, zerolog.New(io.Discard))

	initReq := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"initialize"}`)))
	initRes := httptest.NewRecorder()
	handler.ServeHTTP(initRes, initReq)
	sessionID := initRes.Header().Get("MCP-Session-Id")
	require.NotEmpty(t, sessionID)

	deleteReq := httptest.NewRequest(http.MethodDelete, "/memory/mcp", nil)
	deleteReq.Header.Set("MCP-Session-Id", sessionID)
	deleteRes := httptest.NewRecorder()
	handler.ServeHTTP(deleteRes, deleteReq)
	require.Equal(t, http.StatusNoContent, deleteRes.Code)

	toolsReq := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	toolsReq.Header.Set("MCP-Session-Id", sessionID)
	toolsRes := httptest.NewRecorder()
	handler.ServeHTTP(toolsRes, toolsReq)
	require.Equal(t, http.StatusNotFound, toolsRes.Code)
	require.Contains(t, toolsRes.Body.String(), "session_not_found")
}

func TestSSEToStreamableHTTPBridgeTimesOutWaitingForEndpoint(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/sse", r.URL.Path)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)
		flusher.Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	defer upstream.CloseClientConnections()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	handler := NewSSEToStreamableHTTPBridge(targetURL, "/memory/mcp", "/sse", false, zerolog.New(io.Discard))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))).WithContext(ctx)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusGatewayTimeout, res.Code)
	require.Contains(t, res.Body.String(), "upstream_protocol_timeout")
}

func TestSSEToStreamableHTTPBridgeTimesOutWaitingForResponse(t *testing.T) {
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
			<-r.Context().Done()
		case "/message":
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	handler := NewSSEToStreamableHTTPBridge(targetURL, "/memory/mcp", "/sse", false, zerolog.New(io.Discard))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/memory/mcp", bytes.NewReader(requestBody)).WithContext(ctx)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusGatewayTimeout, res.Code)
	require.Contains(t, res.Body.String(), "upstream_protocol_timeout")
}
