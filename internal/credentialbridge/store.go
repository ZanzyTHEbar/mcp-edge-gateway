package credentialbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type credential struct {
	Resource      string        `json:"resource"`
	Issuer        string        `json:"issuer"`
	TokenEndpoint string        `json:"token_endpoint"`
	ClientID      string        `json:"client_id"`
	Scope         string        `json:"scope"`
	Token         *oauth2.Token `json:"token"`
}

const keystoreService = "mcp-edge-credential-bridge"

var errCredentialAccess = errors.New("MCP credential unavailable")

type credentialStore struct {
	path, key            string
	secretTool, dbusTool string
}

func newCredentialStore(resource, directory string) (*credentialStore, error) {
	secretTool, err := exec.LookPath("secret-tool")
	if err != nil {
		return nil, errors.New("install libsecret-tools: the bridge requires an encrypted Secret Service keystore")
	}
	dbusTool, err := exec.LookPath("gdbus")
	if err != nil {
		return nil, errors.New("install the GLib gdbus tool to check keystore lock state")
	}
	if directory == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		directory = filepath.Join(base, "mcp-edge-credential-bridge")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("bridge state directory must be private (mode 0700), not a symlink")
	}
	key := sha256.Sum256([]byte(resource))
	account := hex.EncodeToString(key[:])
	path := filepath.Join(directory, account)
	if _, err := os.Lstat(path + ".json"); err == nil {
		return nil, errors.New("legacy plaintext credential file exists; revoke and remove it before using the keystore bridge (no automatic migration)")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &credentialStore{path: path, key: account, secretTool: secretTool, dbusTool: dbusTool}, nil
}

func (s *credentialStore) read(ctx context.Context) (*credential, error) {
	data, err := s.secret(ctx, "lookup", nil)
	if err != nil {
		return nil, err
	}
	var stored credential
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, errors.New("invalid credential in keystore; use logout before signing in again")
	}
	return &stored, nil
}

// Secret Service owns persistence and encryption; no secret reaches our files.
// The empty OS lock file serializes rotating refresh tokens across processes.
func (s *credentialStore) update(ctx context.Context, change func(*credential) (*credential, error)) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	previous, err := s.read(ctx)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next, err := change(previous)
	if err != nil || next == previous {
		return err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return errors.New("cannot encode credential for keystore")
	}
	_, err = s.secret(ctx, "store", data)
	return err
}

func (s *credentialStore) remove(ctx context.Context) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = s.secret(ctx, "clear", nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *credentialStore) secret(ctx context.Context, operation string, data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Never request an interactive unlock or create an unprotected collection.
	// The operator unlocks a password-protected default keyring in their session.
	probe := exec.CommandContext(ctx, s.dbusTool, "call", "--session", "--dest", "org.freedesktop.secrets",
		"--object-path", "/org/freedesktop/secrets/aliases/default", "--method", "org.freedesktop.DBus.Properties.Get",
		"org.freedesktop.Secret.Collection", "Locked")
	state, err := probe.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil || strings.TrimSpace(string(state)) != "(<false>,)" {
		return nil, errors.New("encrypted Secret Service keystore is unavailable or locked; unlock the password-protected default keyring in this user session")
	}
	args := []string{operation}
	if operation == "store" {
		args = append(args, "--label=MCP Edge OAuth credential", "--collection=default")
	}
	args = append(args, "service", keystoreService, "resource", s.key)
	command := exec.CommandContext(ctx, s.secretTool, args...)
	command.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	result, err := command.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		var exit *exec.ExitError
		if (operation == "lookup" || operation == "clear") && errors.As(err, &exit) && exit.ExitCode() == 1 && stderr.Len() == 0 {
			return nil, os.ErrNotExist
		}
		// Helper output may contain secret material. Never include it in errors.
		return nil, errors.New("Secret Service keystore operation failed; no filesystem credential fallback is allowed")
	}
	return result, nil
}

func (s *credentialStore) lock(ctx context.Context) (func(), error) {
	path := s.path + ".lock"
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("credential lock must be a regular owner-only file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	for {
		locked, err := tryFileLock(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if locked {
			return func() { releaseFileLock(f); f.Close() }, nil
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("waiting for credential lock: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (c *Client) token(ctx context.Context, rejected string) (*oauth2.Token, error) {
	var token *oauth2.Token
	err := c.store.update(ctx, func(stored *credential) (*credential, error) {
		if stored == nil {
			return nil, errors.New("not signed in; run mcp-edge-credential-bridge login --url with this service URL")
		}
		if stored.Resource != c.resource || stored.ClientID == "" || stored.Token == nil || stored.Token.AccessToken == "" || !strings.EqualFold(stored.Token.TokenType, "Bearer") {
			return nil, errors.New("credential does not match this service; run logout and login again")
		}
		if _, err := c.edgeURL(stored.Issuer); err != nil {
			return nil, err
		}
		if _, err := c.edgeURL(stored.TokenEndpoint); err != nil {
			return nil, err
		}
		token = stored.Token
		if token.Valid() && (rejected == "" || token.AccessToken != rejected) {
			return stored, nil
		}
		if token.RefreshToken == "" {
			return nil, errors.New("no refresh token available; run login again")
		}
		copyToken := *token
		copyToken.Expiry = time.Now().Add(-time.Minute)
		cfg := oauth2.Config{ClientID: stored.ClientID, Endpoint: oauth2.Endpoint{TokenURL: stored.TokenEndpoint, AuthStyle: oauth2.AuthStyleInParams}}
		client := &http.Client{Timeout: 30 * time.Second, Transport: &resourceTransport{resource: c.resource}, CheckRedirect: c.http.CheckRedirect}
		tokenCtx := context.WithValue(ctx, oauth2.HTTPClient, client)
		fresh, err := cfg.TokenSource(tokenCtx, &copyToken).Token()
		if err != nil {
			return nil, oauthError("refresh", err)
		}
		if fresh.AccessToken == "" || !strings.EqualFold(fresh.TokenType, "Bearer") {
			return nil, errors.New("refresh did not return a bearer token")
		}
		next := *stored
		next.Token = fresh
		token = fresh
		return &next, nil
	})
	return token, err
}

// oauth2.Config handles rotation and token parsing; add the RFC 8707 resource
// that Config.TokenSource does not otherwise include on refresh requests.
type resourceTransport struct{ resource string }

func (t *resourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	req.Body.Close()
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	form.Set("resource", t.resource)
	clone := req.Clone(req.Context())
	encoded := form.Encode()
	clone.Body = io.NopCloser(strings.NewReader(encoded))
	clone.ContentLength = int64(len(encoded))
	return http.DefaultTransport.RoundTrip(clone)
}

type authorizedTransport struct{ client *Client }

func (t *authorizedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != t.client.resource {
		return nil, errors.New("refusing to send a credential outside its MCP resource")
	}
	token, err := t.client.token(req.Context(), "")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCredentialAccess, err)
	}
	send := func(token *oauth2.Token, retry bool) (*http.Response, error) {
		clone := req.Clone(req.Context())
		if retry && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			clone.Body = body
		}
		clone.Header.Set("Authorization", "Bearer "+token.AccessToken)
		return http.DefaultTransport.RoundTrip(clone)
	}
	res, err := send(token, false)
	if err != nil || res.StatusCode != http.StatusUnauthorized || req.Body != nil && req.GetBody == nil {
		return res, err
	}
	res.Body.Close()
	fresh, err := t.client.token(req.Context(), token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCredentialAccess, err)
	}
	return send(fresh, true)
}
