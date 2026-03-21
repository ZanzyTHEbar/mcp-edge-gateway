package edge

import (
	"bufio"
	"crypto/tls"
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
		Transport: newEdgeTransport(insecureSkipVerify),
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

func NewLegacySSEEndpointProxy(target *url.URL, publicPath string, upstreamPath string, insecureSkipVerify bool, logger zerolog.Logger) http.Handler {
	transport := newEdgeTransport(insecureSkipVerify)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamURL := *target
		upstreamURL.Path = rewriteProxyPath(r.URL.Path, publicPath, upstreamPath)
		upstreamURL.RawPath = upstreamURL.EscapedPath()
		upstreamURL.RawQuery = r.URL.RawQuery

		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), nil)
		if err != nil {
			logger.Error().Err(err).Str("path", r.URL.Path).Msg("failed to create legacy sse upstream request")
			writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to reach upstream tenant service")
			return
		}
		req.Header = r.Header.Clone()
		req.Host = target.Host
		sanitizeProxyHeaders(req.Header)

		resp, err := transport.RoundTrip(req)
		if err != nil {
			logger.Error().Err(err).Str("path", r.URL.Path).Msg("legacy sse proxy request failed")
			writeJSONError(w, http.StatusBadGateway, "upstream_proxy_failed", "unable to reach upstream tenant service")
			return
		}
		defer resp.Body.Close()

		copyResponseHeaders(w.Header(), resp.Header)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)

		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(strings.ToLower(contentType), "text/event-stream") {
			_, _ = io.Copy(w, resp.Body)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			writeJSONError(w, http.StatusInternalServerError, "streaming_unsupported", "streaming response writer is required")
			return
		}

		reader := bufio.NewReader(resp.Body)
		expectEndpointData := false
		for {
			line, readErr := reader.ReadString('\n')
			if len(line) > 0 {
				switch {
				case strings.HasPrefix(line, "event:"):
					expectEndpointData = strings.TrimSpace(strings.TrimPrefix(line, "event:")) == "endpoint"
				case expectEndpointData && strings.HasPrefix(line, "data:"):
					line = rewriteLegacyEndpointEventLine(line, publicPath, upstreamPath)
				case line == "\n" || line == "\r\n":
					expectEndpointData = false
				}
				if _, writeErr := io.WriteString(w, line); writeErr != nil {
					return
				}
				flusher.Flush()
			}
			if readErr != nil {
				return
			}
		}
	})
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

func rewriteLegacyEndpointEventLine(line string, publicPath string, upstreamPath string) string {
	const dataPrefix = "data:"
	value := strings.TrimSpace(strings.TrimPrefix(line, dataPrefix))
	if strings.HasPrefix(value, upstreamPath) {
		return dataPrefix + " " + publicPath + strings.TrimPrefix(value, upstreamPath) + "\n"
	}
	parsedValue, err := url.Parse(value)
	if err == nil && strings.HasPrefix(parsedValue.Path, upstreamPath) {
		parsedValue.Path = publicPath + strings.TrimPrefix(parsedValue.Path, upstreamPath)
		return dataPrefix + " " + parsedValue.String() + "\n"
	}
	return line
}
