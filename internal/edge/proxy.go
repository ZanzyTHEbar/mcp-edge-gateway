package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const sseBridgeEndpointTimeout = 10 * time.Second

const sseBridgeResponseTimeout = 30 * time.Second

const sseBridgeSessionIdleTimeout = 10 * time.Minute

const sseBridgeMaxSessions = 128

var errSSEBridgeSessionNotFound = errors.New("sse bridge session not found")

func NewStreamSafeReverseProxy(target *url.URL, publicPath string, upstreamPath string, insecureSkipVerify bool, logger zerolog.Logger) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1,
		Transport:     newEdgeTransport(insecureSkipVerify),
	}
	proxy.Rewrite = func(req *httputil.ProxyRequest) {
		req.SetURL(target)
		req.Out.Host = target.Host
		req.SetXForwarded()
		sanitizeProxyHeaders(req.Out.Header)
		applyUpstreamIdentityHeaders(req.Out.Header, req.In.Context())
		req.Out.URL.Path = rewriteProxyPath(req.In.URL.Path, publicPath, upstreamPath)
		req.Out.URL.RawPath = req.Out.URL.EscapedPath()
		req.Out.URL.RawQuery = req.In.URL.RawQuery
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error().
			Err(err).
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Msg("edge proxy request failed")
		writeUpstreamTransportError(w, err, "unable to reach upstream tenant service")
	}
	return proxy
}

func NewSSEToStreamableHTTPBridge(target *url.URL, publicPath string, upstreamPath string, insecureSkipVerify bool, logger zerolog.Logger) http.Handler {
	return &sseToStreamableHTTPBridge{
		target:       target,
		publicPath:   publicPath,
		upstreamPath: upstreamPath,
		transport:    newEdgeTransport(insecureSkipVerify),
		logger:       logger,
		sessions:     make(map[string]*upstreamSSESession),
	}
}

type sseToStreamableHTTPBridge struct {
	target       *url.URL
	publicPath   string
	upstreamPath string
	transport    http.RoundTripper
	logger       zerolog.Logger

	mu       sync.Mutex
	sessions map[string]*upstreamSSESession
}

type upstreamSSESession struct {
	id       string
	endpoint *url.URL
	reader   *bufio.Reader
	close    func()
	mu       sync.Mutex
	lastUsed time.Time
}

func (b *sseToStreamableHTTPBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		b.handlePost(w, r)
	case http.MethodGet:
		bridgeStreamableGet(w, r, b.target, b.publicPath, b.upstreamPath, b.transport, b.logger)
	case http.MethodDelete:
		b.handleDelete(w, r)
	default:
		w.Header().Set("Allow", "DELETE, GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "memory bridge supports DELETE, GET, and POST")
	}
}

func (b *sseToStreamableHTTPBridge) handlePost(w http.ResponseWriter, r *http.Request) {
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_body", "unable to read request body")
		return
	}
	if jsonRPCBatch(requestBody) {
		writeJSONError(w, http.StatusBadRequest, "unsupported_batch", "memory bridge does not support JSON-RPC batch requests")
		return
	}

	method, _ := jsonRPCMethod(requestBody)
	sessionID := strings.TrimSpace(r.Header.Get("MCP-Session-Id"))
	session, err := b.sessionForRequest(r, sessionID, method == "initialize")
	if err != nil {
		if errors.Is(err, errSSEBridgeSessionNotFound) {
			writeJSONError(w, http.StatusNotFound, "session_not_found", "memory bridge session is not initialized")
			return
		}
		b.logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge failed to establish upstream session")
		if isCanceledError(err) {
			return
		}
		if isTimeoutError(err) {
			writeJSONError(w, http.StatusGatewayTimeout, "upstream_protocol_timeout", "memory upstream timed out before exposing an SSE endpoint")
			return
		}
		writeJSONError(w, http.StatusBadGateway, "upstream_protocol_error", "memory upstream did not expose a usable SSE endpoint")
		return
	}
	w.Header().Set("MCP-Session-Id", session.id)

	session.mu.Lock()
	defer session.mu.Unlock()
	b.forwardSessionPost(w, r, session, requestBody)
}

func (b *sseToStreamableHTTPBridge) handleDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimSpace(r.Header.Get("MCP-Session-Id"))
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_session", "MCP-Session-Id header is required")
		return
	}
	b.mu.Lock()
	session := b.sessions[sessionID]
	if session != nil {
		delete(b.sessions, sessionID)
	}
	b.mu.Unlock()
	if session != nil {
		session.close()
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (b *sseToStreamableHTTPBridge) sessionForRequest(r *http.Request, sessionID string, initialize bool) (*upstreamSSESession, error) {
	b.pruneIdleSessions(time.Now())
	if sessionID != "" && !initialize {
		b.mu.Lock()
		session := b.sessions[sessionID]
		if session != nil {
			session.lastUsed = time.Now()
		}
		b.mu.Unlock()
		if session != nil {
			return session, nil
		}
		return nil, errSSEBridgeSessionNotFound
	}

	if sessionID == "" || initialize {
		var err error
		sessionID, err = randomSessionID()
		if err != nil {
			return nil, err
		}
	}
	endpoint, reader, closeSSE, err := openUpstreamSSEEndpointWithContext(context.Background(), r, b.target, b.publicPath, b.upstreamPath, b.transport, b.logger)
	if err != nil {
		return nil, err
	}
	session := &upstreamSSESession{id: sessionID, endpoint: endpoint, reader: reader, close: closeSSE, lastUsed: time.Now()}
	b.mu.Lock()
	if old := b.sessions[sessionID]; old != nil {
		old.close()
	}
	b.sessions[sessionID] = session
	b.evictOldestLocked(sseBridgeMaxSessions)
	b.mu.Unlock()
	return session, nil
}

func (b *sseToStreamableHTTPBridge) pruneIdleSessions(now time.Time) {
	b.mu.Lock()
	var expired []*upstreamSSESession
	for id, session := range b.sessions {
		if now.Sub(session.lastUsed) > sseBridgeSessionIdleTimeout {
			delete(b.sessions, id)
			expired = append(expired, session)
		}
	}
	b.mu.Unlock()
	for _, session := range expired {
		session.close()
	}
}

func (b *sseToStreamableHTTPBridge) evictOldestLocked(maxSessions int) {
	for len(b.sessions) > maxSessions {
		var oldest *upstreamSSESession
		for _, session := range b.sessions {
			if oldest == nil || session.lastUsed.Before(oldest.lastUsed) {
				oldest = session
			}
		}
		if oldest == nil {
			return
		}
		delete(b.sessions, oldest.id)
		oldest.close()
	}
}

func (b *sseToStreamableHTTPBridge) removeSession(session *upstreamSSESession) {
	b.mu.Lock()
	if b.sessions[session.id] == session {
		delete(b.sessions, session.id)
	}
	b.mu.Unlock()
	session.close()
}

func (b *sseToStreamableHTTPBridge) Close() {
	b.mu.Lock()
	sessions := make([]*upstreamSSESession, 0, len(b.sessions))
	for _, session := range b.sessions {
		sessions = append(sessions, session)
	}
	b.sessions = make(map[string]*upstreamSSESession)
	b.mu.Unlock()
	for _, session := range sessions {
		session.close()
	}
}

func (b *sseToStreamableHTTPBridge) forwardSessionPost(w http.ResponseWriter, r *http.Request, session *upstreamSSESession, requestBody []byte) {
	postReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, session.endpoint.String(), bytes.NewReader(requestBody))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to build upstream request")
		return
	}
	postReq.Header = r.Header.Clone()
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Accept", "application/json, text/event-stream")
	sanitizeProxyHeaders(postReq.Header)
	applyUpstreamIdentityHeaders(postReq.Header, r.Context())
	postReq.Host = b.target.Host

	resp, err := b.transport.RoundTrip(postReq)
	if err != nil {
		b.logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge upstream POST failed")
		b.removeSession(session)
		writeUpstreamTransportError(w, err, "unable to reach upstream tenant service")
		return
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		b.removeSession(session)
		writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to read upstream response")
		return
	}
	if len(bytes.TrimSpace(responseBody)) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if _, hasRequestID := jsonRPCID(requestBody); !hasRequestID {
			copyResponseHeaders(w.Header(), resp.Header)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("MCP-Session-Id", session.id)
			w.Header().Del("Content-Length")
			w.WriteHeader(resp.StatusCode)
			return
		}
		var waitErr error
		responseBody, waitErr = readSSEJSONRPCResponse(r.Context(), session.reader, requestBody, session.close)
		if waitErr != nil {
			b.logger.Error().Err(waitErr).Str("path", r.URL.Path).Msg("sse bridge failed to read upstream JSON-RPC response")
			b.removeSession(session)
			if isCanceledError(waitErr) {
				return
			}
			if isTimeoutError(waitErr) {
				writeJSONError(w, http.StatusGatewayTimeout, "upstream_protocol_timeout", "memory upstream timed out before returning a JSON-RPC response")
				return
			}
			writeJSONError(w, http.StatusBadGateway, "upstream_protocol_error", "memory upstream did not return a JSON-RPC response")
			return
		}
		resp.StatusCode = http.StatusOK
		resp.Header.Set("Content-Type", "application/json")
	}
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("MCP-Session-Id", session.id)
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(responseBody)
}

func bridgeStreamablePost(w http.ResponseWriter, r *http.Request, target *url.URL, publicPath string, upstreamPath string, transport http.RoundTripper, logger zerolog.Logger) {
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_body", "unable to read request body")
		return
	}
	if jsonRPCBatch(requestBody) {
		writeJSONError(w, http.StatusBadRequest, "unsupported_batch", "memory bridge does not support JSON-RPC batch requests")
		return
	}
	upstreamEndpoint, sseReader, closeSSE, err := openUpstreamSSEEndpoint(r, target, publicPath, upstreamPath, transport, logger)
	if err != nil {
		logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge failed to establish upstream session")
		if isCanceledError(err) {
			return
		}
		if isTimeoutError(err) {
			writeJSONError(w, http.StatusGatewayTimeout, "upstream_protocol_timeout", "memory upstream timed out before exposing an SSE endpoint")
			return
		}
		writeJSONError(w, http.StatusBadGateway, "upstream_protocol_error", "memory upstream did not expose a usable SSE endpoint")
		return
	}
	defer closeSSE()

	postReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamEndpoint.String(), bytes.NewReader(requestBody))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to build upstream request")
		return
	}
	postReq.Header = r.Header.Clone()
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Accept", "application/json, text/event-stream")
	sanitizeProxyHeaders(postReq.Header)
	applyUpstreamIdentityHeaders(postReq.Header, r.Context())
	postReq.Host = target.Host

	resp, err := transport.RoundTrip(postReq)
	if err != nil {
		logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge upstream POST failed")
		writeUpstreamTransportError(w, err, "unable to reach upstream tenant service")
		return
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to read upstream response")
		return
	}
	if len(bytes.TrimSpace(responseBody)) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if _, hasRequestID := jsonRPCID(requestBody); !hasRequestID {
			copyResponseHeaders(w.Header(), resp.Header)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Del("Content-Length")
			w.WriteHeader(resp.StatusCode)
			return
		}
		var waitErr error
		responseBody, waitErr = readSSEJSONRPCResponse(r.Context(), sseReader, requestBody, closeSSE)
		if waitErr != nil {
			logger.Error().Err(waitErr).Str("path", r.URL.Path).Msg("sse bridge failed to read upstream JSON-RPC response")
			if isCanceledError(waitErr) {
				return
			}
			if isTimeoutError(waitErr) {
				writeJSONError(w, http.StatusGatewayTimeout, "upstream_protocol_timeout", "memory upstream timed out before returning a JSON-RPC response")
				return
			}
			writeJSONError(w, http.StatusBadGateway, "upstream_protocol_error", "memory upstream did not return a JSON-RPC response")
			return
		}
		resp.StatusCode = http.StatusOK
		resp.Header.Set("Content-Type", "application/json")
	}
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(responseBody)
}

func bridgeStreamableGet(w http.ResponseWriter, r *http.Request, target *url.URL, publicPath string, upstreamPath string, transport http.RoundTripper, logger zerolog.Logger) {
	upstreamURL := *target
	upstreamURL.Path = rewriteProxyPath(r.URL.Path, publicPath, upstreamPath)
	upstreamURL.RawPath = upstreamURL.EscapedPath()
	upstreamURL.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to build upstream request")
		return
	}
	req.Header = r.Header.Clone()
	req.Header.Set("Accept", "text/event-stream")
	sanitizeProxyHeaders(req.Header)
	applyUpstreamIdentityHeaders(req.Header, r.Context())
	req.Host = target.Host
	resp, err := transport.RoundTrip(req)
	if err != nil {
		logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge upstream GET failed")
		writeUpstreamTransportError(w, err, "unable to reach upstream tenant service")
		return
	}
	defer resp.Body.Close()
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		copyResponseHeaders(w.Header(), resp.Header)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming_unsupported", "streaming response writer is required")
		return
	}
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	reader := bufio.NewReader(resp.Body)
	if err := copySSEWithoutEndpointEvents(w, flusher, reader); err != nil {
		logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge failed to stream upstream events")
	}
}

func copySSEWithoutEndpointEvents(w io.Writer, flusher http.Flusher, reader *bufio.Reader) error {
	var eventLines []string
	eventName := "message"
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			if line == "\n" || line == "\r\n" {
				if eventName != "endpoint" {
					for _, eventLine := range eventLines {
						if _, err := io.WriteString(w, eventLine); err != nil {
							return err
						}
					}
					if _, err := io.WriteString(w, line); err != nil {
						return err
					}
					flusher.Flush()
				}
				eventLines = eventLines[:0]
				eventName = "message"
			} else {
				eventLines = append(eventLines, line)
				if strings.HasPrefix(line, "event:") {
					eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				if len(eventLines) > 0 && eventName != "endpoint" {
					for _, eventLine := range eventLines {
						if _, err := io.WriteString(w, eventLine); err != nil {
							return err
						}
					}
					flusher.Flush()
				}
				return nil
			}
			return readErr
		}
	}
}

func openUpstreamSSEEndpoint(r *http.Request, target *url.URL, publicPath string, upstreamPath string, transport http.RoundTripper, logger zerolog.Logger) (*url.URL, *bufio.Reader, func(), error) {
	return openUpstreamSSEEndpointWithContext(r.Context(), r, target, publicPath, upstreamPath, transport, logger)
}

func openUpstreamSSEEndpointWithContext(ctx context.Context, r *http.Request, target *url.URL, publicPath string, upstreamPath string, transport http.RoundTripper, logger zerolog.Logger) (*url.URL, *bufio.Reader, func(), error) {
	upstreamURL := *target
	upstreamURL.Path = rewriteProxyPath(publicPath, publicPath, upstreamPath)
	upstreamURL.RawPath = upstreamURL.EscapedPath()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header = r.Header.Clone()
	req.Header.Set("Accept", "text/event-stream")
	sanitizeProxyHeaders(req.Header)
	applyUpstreamIdentityHeaders(req.Header, r.Context())
	req.Host = target.Host
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, nil, nil, err
	}
	closeSSE := func() { _ = resp.Body.Close() }
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		closeSSE()
		return nil, nil, nil, fmt.Errorf("upstream SSE returned status %d", resp.StatusCode)
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		closeSSE()
		return nil, nil, nil, fmt.Errorf("upstream SSE returned content type %q", resp.Header.Get("Content-Type"))
	}
	reader := bufio.NewReader(resp.Body)
	endpoint, err := readSSEEndpointEvent(r.Context(), reader, closeSSE)
	if err != nil {
		closeSSE()
		return nil, nil, nil, err
	}
	endpointURL, err := normalizeUpstreamEndpoint(target, endpoint)
	if err != nil {
		closeSSE()
		return nil, nil, nil, err
	}
	logger.Debug().Str("upstream_endpoint", endpointURL.Redacted()).Msg("sse bridge upstream endpoint established")
	return endpointURL, reader, closeSSE, nil
}

func readSSEEndpointEvent(ctx context.Context, reader *bufio.Reader, closeSSE func()) (string, error) {
	readCtx, cancel := context.WithTimeout(ctx, sseBridgeEndpointTimeout)
	defer cancel()

	type result struct {
		endpoint string
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		endpoint, err := readSSEEndpointEventBlocking(reader)
		resultCh <- result{endpoint: endpoint, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.endpoint, result.err
	case <-readCtx.Done():
		closeSSE()
		return "", readCtx.Err()
	}
}

func readSSEEndpointEventBlocking(reader *bufio.Reader) (string, error) {
	expectEndpointData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(line, "event:") {
			expectEndpointData = strings.TrimSpace(strings.TrimPrefix(line, "event:")) == "endpoint"
			continue
		}
		if expectEndpointData && strings.HasPrefix(line, "data:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if value == "" {
				return "", errors.New("empty upstream endpoint event")
			}
			return value, nil
		}
		if line == "\n" || line == "\r\n" {
			expectEndpointData = false
		}
	}
}

func readSSEJSONRPCResponse(ctx context.Context, reader *bufio.Reader, requestBody []byte, closeSSE func()) ([]byte, error) {
	readCtx, cancel := context.WithTimeout(ctx, sseBridgeResponseTimeout)
	defer cancel()

	type result struct {
		payload []byte
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		payload, err := readSSEJSONRPCResponseBlocking(reader, requestBody)
		resultCh <- result{payload: payload, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.payload, result.err
	case <-readCtx.Done():
		closeSSE()
		return nil, readCtx.Err()
	}
}

func readSSEJSONRPCResponseBlocking(reader *bufio.Reader, requestBody []byte) ([]byte, error) {
	requestID, hasRequestID := jsonRPCID(requestBody)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		if !hasRequestID {
			return payload, nil
		}
		responseID, ok := jsonRPCID(payload)
		if ok && fmt.Sprint(responseID) == fmt.Sprint(requestID) {
			return payload, nil
		}
	}
}

func jsonRPCBatch(body []byte) bool {
	var payload []json.RawMessage
	return json.Unmarshal(body, &payload) == nil
}

func jsonRPCID(body []byte) (any, bool) {
	var payload struct {
		ID any `json:"id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.ID == nil {
		return nil, false
	}
	return payload.ID, true
}

func jsonRPCMethod(body []byte) (string, bool) {
	var payload struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Method == "" {
		return "", false
	}
	return payload.Method, true
}

func randomSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isCanceledError(err error) bool {
	return errors.Is(err, context.Canceled)
}

func writeUpstreamTransportError(w http.ResponseWriter, err error, message string) {
	if isTimeoutError(err) {
		writeJSONError(w, http.StatusGatewayTimeout, "upstream_timeout", message)
		return
	}
	writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", message)
}

func normalizeUpstreamEndpoint(target *url.URL, endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if parsed.IsAbs() {
		if parsed.Scheme != target.Scheme || parsed.Host != target.Host {
			return nil, fmt.Errorf("upstream endpoint %q escapes tenant origin", endpoint)
		}
		return parsed, nil
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return nil, fmt.Errorf("upstream endpoint %q is not absolute-path or same-origin URL", endpoint)
	}
	out := *target
	out.Path = parsed.Path
	out.RawPath = parsed.EscapedPath()
	out.RawQuery = parsed.RawQuery
	return &out, nil
}

func newEdgeTransport(insecureSkipVerify bool) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: sseBridgeResponseTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
	}
}

func sanitizeProxyHeaders(header http.Header) {
	header.Del("Authorization")
	header.Del("Cookie")
	header.Del("Accept-Encoding")
	stripIdentityContextHeaders(header)
	header.Set("Cache-Control", "no-store")
}

func copyResponseHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func rewriteProxyPath(requestPath string, publicPath string, upstreamPath string) string {
	if requestPath == publicPath {
		return upstreamPath
	}

	trimmedPath := strings.TrimPrefix(requestPath, publicPath)
	if trimmedPath == "" {
		return upstreamPath
	}

	if strings.HasSuffix(upstreamPath, "/") {
		return upstreamPath + strings.TrimPrefix(trimmedPath, "/")
	}

	return upstreamPath + trimmedPath
}
