package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRewriteProxyPathTranslatesActualBudgetPath(t *testing.T) {
	t.Parallel()

	require.Equal(t, "/http", rewriteProxyPath("/actualbudget/mcp", "/actualbudget/mcp", "/http"))
	require.Equal(t, "/http/tools/list", rewriteProxyPath("/actualbudget/mcp/tools/list", "/actualbudget/mcp", "/http"))
}

func TestRewriteLegacyEndpointEventLine(t *testing.T) {
	t.Parallel()

	line := rewriteLegacyEndpointEventLine("data: /sse?sessionid=abc\n", "/memory/mcp", "/sse")
	require.Equal(t, "data: /memory/mcp?sessionid=abc\n", line)
}

func TestLegacySSEEndpointProxyRewritesEndpointEvent(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/sse", r.URL.Path)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: endpoint\n")
		_, _ = io.WriteString(w, "data: /sse?sessionid=test-session\n\n")
	}))
	defer upstream.Close()

	targetURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	handler := NewLegacySSEEndpointProxy(
		targetURL,
		"/memory/mcp",
		"/sse",
		false,
		zerolog.New(io.Discard),
	)

	req := httptest.NewRequest(http.MethodGet, "/memory/mcp", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(t, "text/event-stream", res.Header().Get("Content-Type"))
	require.Contains(t, res.Body.String(), "event: endpoint")
	require.Contains(t, res.Body.String(), "data: /memory/mcp?sessionid=test-session")
}
