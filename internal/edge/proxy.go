package edge

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

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
		writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to reach upstream tenant service")
	}
	return proxy
}

func NewSSEToStreamableHTTPBridge(target *url.URL, publicPath string, upstreamPath string, insecureSkipVerify bool, logger zerolog.Logger) http.Handler {
	transport := newEdgeTransport(insecureSkipVerify)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			bridgeStreamablePost(w, r, target, publicPath, upstreamPath, transport, logger)
		case http.MethodGet:
			bridgeStreamableGet(w, r, target, publicPath, upstreamPath, transport, logger)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "memory bridge supports GET and POST")
		}
	})
}

func bridgeStreamablePost(w http.ResponseWriter, r *http.Request, target *url.URL, publicPath string, upstreamPath string, transport http.RoundTripper, logger zerolog.Logger) {
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_body", "unable to read request body")
		return
	}
	upstreamEndpoint, sseReader, closeSSE, err := openUpstreamSSEEndpoint(r, target, publicPath, upstreamPath, transport, logger)
	if err != nil {
		logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge failed to establish upstream session")
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
	postReq.Host = target.Host

	resp, err := transport.RoundTrip(postReq)
	if err != nil {
		logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge upstream POST failed")
		writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to reach upstream tenant service")
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
		responseBody, waitErr = readSSEJSONRPCResponse(sseReader, requestBody)
		if waitErr != nil {
			logger.Error().Err(waitErr).Str("path", r.URL.Path).Msg("sse bridge failed to read upstream JSON-RPC response")
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
	req.Host = target.Host
	resp, err := transport.RoundTrip(req)
	if err != nil {
		logger.Error().Err(err).Str("path", r.URL.Path).Msg("sse bridge upstream GET failed")
		writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to reach upstream tenant service")
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
	upstreamURL := *target
	upstreamURL.Path = rewriteProxyPath(publicPath, publicPath, upstreamPath)
	upstreamURL.RawPath = upstreamURL.EscapedPath()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header = r.Header.Clone()
	req.Header.Set("Accept", "text/event-stream")
	sanitizeProxyHeaders(req.Header)
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
	endpoint, err := readSSEEndpointEvent(reader)
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

func readSSEEndpointEvent(reader *bufio.Reader) (string, error) {
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

func readSSEJSONRPCResponse(reader *bufio.Reader, requestBody []byte) ([]byte, error) {
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

func jsonRPCID(body []byte) (any, bool) {
	var payload struct {
		ID any `json:"id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.ID == nil {
		return nil, false
	}
	return payload.ID, true
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
