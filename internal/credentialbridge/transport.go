package credentialbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxMessageBytes = 16 << 20

// wireMessage only inspects transport state. The original bytes are forwarded
// unchanged, including unknown capabilities, extensions, IDs, and metadata.
type wireMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
}

type requestParams struct {
	ProtocolVersion string `json:"protocolVersion"`
	Meta            struct {
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"_meta"`
}

type relay struct {
	client                         *http.Client
	endpoint                       string
	output                         io.Writer
	writeMu                        sync.Mutex
	stateMu                        sync.Mutex
	session, version, initializeID string
	listenOnce                     sync.Once
	workers                        sync.WaitGroup
	fail                           chan error
}

// Serve relays one stdio session without manufacturing tools or capabilities.
// POST responses and the optional server-initiated SSE stream share a serialized
// stdout writer. Cancellation closes stdin/stdout and all HTTP request contexts.
func (c *Client) Serve(ctx context.Context, input io.ReadCloser, output io.WriteCloser) error {
	if _, err := c.token(ctx, ""); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r := &relay{
		endpoint: c.resource, output: output,
		client: &http.Client{Transport: &authorizedTransport{client: c}, CheckRedirect: c.http.CheckRedirect},
		fail:   make(chan error, 1),
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		input.Close()
		output.Close()
	}()
	defer close(done)
	requests := make(chan struct{}, 32)
	readDone := make(chan error, 1)
	readerExited := make(chan struct{})
	go func() {
		defer close(readerExited)
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 64<<10), maxMessageBytes)
		for scanner.Scan() {
			body := bytes.Clone(scanner.Bytes())
			var message wireMessage
			if err := json.Unmarshal(body, &message); err != nil || message.JSONRPC != "2.0" {
				readDone <- errors.New("stdio input must be newline-delimited JSON-RPC 2.0")
				return
			}
			// Initialization ordering is protocol-significant. Later requests must
			// not overtake notifications/initialized on separate HTTP connections.
			if message.Method == "initialize" || message.Method == "notifications/initialized" {
				if err := r.post(ctx, body, message); err != nil {
					readDone <- err
					return
				}
				continue
			}
			select {
			case requests <- struct{}{}:
			case <-ctx.Done():
				readDone <- ctx.Err()
				return
			}
			r.workers.Add(1)
			go func() {
				defer r.workers.Done()
				defer func() { <-requests }()
				if err := r.post(ctx, body, message); err != nil {
					r.failed(err)
				}
			}()
		}
		readDone <- scanner.Err()
	}()
	var result error
	select {
	case result = <-r.fail:
	case result = <-readDone:
	case <-ctx.Done():
		result = ctx.Err()
	}
	cancel()
	input.Close()
	output.Close()
	// The reader must finish before Wait, since it owns additions to workers.
	<-readerExited
	r.workers.Wait()
	r.closeSession()
	if errors.Is(result, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return result
}

func (r *relay) failed(err error) {
	select {
	case r.fail <- err:
	default:
	}
}

func (r *relay) headers(req *http.Request) {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if r.session != "" {
		req.Header.Set("Mcp-Session-Id", r.session)
	}
	if r.version != "" {
		req.Header.Set("MCP-Protocol-Version", r.version)
	}
}

func (r *relay) post(ctx context.Context, body []byte, message wireMessage) error {
	var params requestParams
	_ = json.Unmarshal(message.Params, &params)
	if message.Method == "initialize" {
		r.stateMu.Lock()
		r.initializeID = string(message.ID)
		r.version = params.ProtocolVersion
		r.stateMu.Unlock()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	r.headers(req)
	if params.Meta.ProtocolVersion != "" {
		req.Header.Set("MCP-Protocol-Version", params.Meta.ProtocolVersion)
	}
	res, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("MCP POST failed: %w", err)
	}
	defer res.Body.Close()
	if session := res.Header.Get("Mcp-Session-Id"); session != "" {
		r.stateMu.Lock()
		previous := r.session
		if previous == "" {
			r.session = session
		}
		r.stateMu.Unlock()
		if previous != "" && previous != session {
			return errors.New("MCP server changed session ID")
		}
	}
	mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if mediaType == "application/json" {
		data, err := io.ReadAll(io.LimitReader(res.Body, maxMessageBytes+1))
		if err != nil {
			return err
		}
		if _, err := r.write(data); err != nil {
			return err
		}
	} else if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("MCP POST returned HTTP %d", res.StatusCode)
	} else if mediaType == "text/event-stream" {
		responseID := ""
		if message.Method != "" {
			responseID = string(message.ID)
		}
		if _, _, err := r.sse(res.Body, responseID); err != nil {
			return err
		}
	} else if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusNoContent {
		return errors.New("MCP server returned neither JSON nor an SSE stream")
	}
	if message.Method == "notifications/initialized" {
		r.listenOnce.Do(func() {
			r.stateMu.Lock()
			version := r.version
			r.stateMu.Unlock()
			if version >= "2026-07-28" {
				return
			}
			r.workers.Add(1)
			go func() {
				defer r.workers.Done()
				if err := r.listen(ctx); err != nil && ctx.Err() == nil {
					r.failed(err)
				}
			}()
		})
	}
	return nil
}

func (r *relay) write(data []byte) (wireMessage, error) {
	if len(data) > maxMessageBytes {
		return wireMessage{}, errors.New("MCP message exceeds 16 MiB")
	}
	var message wireMessage
	if err := json.Unmarshal(data, &message); err != nil || message.JSONRPC != "2.0" {
		return wireMessage{}, errors.New("MCP server returned invalid JSON-RPC")
	}
	r.stateMu.Lock()
	if r.initializeID != "" && message.Method == "" && string(message.ID) == r.initializeID {
		var result struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(message.Result, &result) == nil && result.ProtocolVersion != "" {
			r.version = result.ProtocolVersion
		}
	}
	r.stateMu.Unlock()
	// Compact JSON so even pretty-printed HTTP responses occupy one stdio line.
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return wireMessage{}, err
	}
	compact.WriteByte('\n')
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	_, err := r.output.Write(compact.Bytes())
	return message, err
}

func (r *relay) sse(reader io.Reader, responseID string) (string, bool, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), maxMessageBytes)
	var data []string
	var size int
	var lastID string
	delivered := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if len(data) != 0 {
				message, err := r.write([]byte(strings.Join(data, "\n")))
				if err != nil {
					return lastID, delivered, err
				}
				delivered = true
				if responseID != "" && message.Method == "" && string(message.ID) == responseID {
					return lastID, delivered, nil
				}
			}
			data, size = nil, 0
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "data":
			size += len(value) + 1
			if size > maxMessageBytes {
				return lastID, delivered, errors.New("SSE message exceeds 16 MiB")
			}
			data = append(data, value)
		case "id":
			if !strings.ContainsRune(value, '\x00') {
				lastID = value
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return lastID, delivered, err
	}
	if responseID != "" {
		return lastID, delivered, errors.New("MCP response stream ended before its response; reconnect rather than replay the request")
	}
	return lastID, delivered, nil
}

func (r *relay) listen(ctx context.Context) error {
	lastID := ""
	for retry := 0; retry < 5; retry++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint, nil)
		if err != nil {
			return err
		}
		r.headers(req)
		req.Header.Set("Accept", "text/event-stream")
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
		res, err := r.client.Do(req)
		if err != nil {
			return err
		}
		if res.StatusCode == http.StatusMethodNotAllowed {
			res.Body.Close()
			return nil
		}
		mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if res.StatusCode != http.StatusOK || mediaType != "text/event-stream" {
			res.Body.Close()
			return fmt.Errorf("MCP notification stream returned HTTP %d or invalid content type", res.StatusCode)
		}
		id, delivered, err := r.sse(res.Body, "")
		res.Body.Close()
		if err != nil {
			return err
		}
		if id != "" {
			lastID = id
		}
		if delivered {
			retry = -1
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("MCP notification stream repeatedly disconnected; reconnect the client")
}

func (r *relay) closeSession() {
	r.stateMu.Lock()
	session := r.session
	r.stateMu.Unlock()
	if session == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, r.endpoint, nil)
	r.headers(req)
	if res, err := r.client.Do(req); err == nil {
		res.Body.Close()
	}
}
