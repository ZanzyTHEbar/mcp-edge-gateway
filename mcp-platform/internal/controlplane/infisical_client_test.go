package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestInfisicalClientResolveSecretReference(t *testing.T) {
	t.Parallel()

	loginCalls := 0
	projectCalls := 0
	secretCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/universal-auth/login":
			loginCalls++
			require.Equal(t, http.MethodPost, r.Method)
			writeTestJSON(t, w, map[string]any{
				"accessToken":       "token-123",
				"expiresIn":         3600,
				"accessTokenMaxTTL": 3600,
				"tokenType":         "Bearer",
			})
		case "/api/v1/projects/slug/mcp-platform":
			projectCalls++
			require.Equal(t, "Bearer token-123", r.Header.Get("Authorization"))
			writeTestJSON(t, w, map[string]any{
				"id": "project-123",
			})
		case "/api/v4/secrets":
			secretCalls++
			require.Equal(t, "Bearer token-123", r.Header.Get("Authorization"))
			require.Equal(t, "project-123", r.URL.Query().Get("projectId"))
			require.Equal(t, "prod", r.URL.Query().Get("environment"))
			require.Equal(t, "/platform/mcp-control-plane", r.URL.Query().Get("secretPath"))
			writeTestJSON(t, w, map[string]any{
				"secrets": []map[string]any{
					{
						"secretKey":   "coolify-api-token",
						"secretValue": "coolify-token-abc",
						"secretPath":  "/platform/mcp-control-plane",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	machineSecretPath := filepath.Join(tempDir, "machine-secret.txt")
	localSecretPath := filepath.Join(tempDir, "local-secret.txt")
	require.NoError(t, os.WriteFile(machineSecretPath, []byte("machine-secret"), 0o600))
	require.NoError(t, os.WriteFile(localSecretPath, []byte("local-secret"), 0o600))

	client, err := NewInfisicalClient(Config{
		InfisicalAPIBaseURL:              server.URL,
		InfisicalProjectSlug:             "mcp-platform",
		InfisicalEnvSlug:                 "prod",
		InfisicalMachineClientID:         "machine-id",
		InfisicalMachineClientSecretPath: machineSecretPath,
	}, zerolog.Nop())
	require.NoError(t, err)

	ctx := context.Background()
	secretValue, err := client.ResolveSecretReference(ctx, "/platform/mcp-control-plane/coolify-api-token")
	require.NoError(t, err)
	require.Equal(t, "coolify-token-abc", secretValue)

	secretValue, err = client.ResolveSecretReference(ctx, localSecretPath)
	require.NoError(t, err)
	require.Equal(t, "local-secret", secretValue)

	require.Equal(t, 1, loginCalls)
	require.Equal(t, 1, projectCalls)
	require.Equal(t, 1, secretCalls)
}

func TestInfisicalClientIncludesResponseBodyInHTTPStatusErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "machine identity rejected", http.StatusUnauthorized)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	machineSecretPath := filepath.Join(tempDir, "machine-secret.txt")
	require.NoError(t, os.WriteFile(machineSecretPath, []byte("machine-secret"), 0o600))

	client, err := NewInfisicalClient(Config{
		InfisicalAPIBaseURL:              server.URL,
		InfisicalProjectSlug:             "mcp-platform",
		InfisicalEnvSlug:                 "prod",
		InfisicalMachineClientID:         "machine-id",
		InfisicalMachineClientSecretPath: machineSecretPath,
	}, zerolog.Nop())
	require.NoError(t, err)

	_, err = client.ResolveSecretReference(context.Background(), "/platform/mcp-control-plane/coolify-api-token")
	require.Error(t, err)
	require.ErrorContains(t, err, "machine identity rejected")
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(payload))
}
