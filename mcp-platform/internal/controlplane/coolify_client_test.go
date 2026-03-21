package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestCoolifyClientServiceLifecycleMethods(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer coolify-token", r.Header.Get("Authorization"))

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/services":
			var requestBody CoolifyCreateServiceRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&requestBody))
			require.Equal(t, "mcp-mealie-u-123", requestBody.Name)
			writeTestJSON(t, w, map[string]any{
				"uuid":    "service-123",
				"domains": []string{},
			})

		case r.Method == http.MethodPatch && r.URL.Path == "/services/service-123/envs/bulk":
			var requestBody map[string][]CoolifyEnvVar
			require.NoError(t, json.NewDecoder(r.Body).Decode(&requestBody))
			require.Len(t, requestBody["data"], 1)
			writeTestJSON(t, w, []map[string]any{
				{
					"uuid":  "env-1",
					"key":   "MEALIE_API_TOKEN",
					"value": "secret",
				},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/services/service-123/restart":
			require.Equal(t, "true", r.URL.Query().Get("latest"))
			writeTestJSON(t, w, map[string]any{
				"message": "Service restart request queued.",
			})

		case r.Method == http.MethodDelete && r.URL.Path == "/services/service-123":
			require.Equal(t, "true", r.URL.Query().Get("delete_configurations"))
			require.Equal(t, "true", r.URL.Query().Get("delete_volumes"))
			require.Equal(t, "true", r.URL.Query().Get("docker_cleanup"))
			require.Equal(t, "true", r.URL.Query().Get("delete_connected_networks"))
			writeTestJSON(t, w, map[string]any{
				"message": "Service deletion request queued.",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewCoolifyClient(server.URL, "coolify-token", zerolog.Nop())
	require.NoError(t, err)

	createResponse, err := client.CreateService(context.Background(), CoolifyCreateServiceRequest{
		Type:        "docker-compose",
		Name:        "mcp-mealie-u-123",
		ProjectUUID: "project-123",
	})
	require.NoError(t, err)
	require.Equal(t, "service-123", createResponse.UUID)

	envResponse, err := client.UpdateServiceEnvsBulk(context.Background(), "service-123", []CoolifyEnvVar{
		{
			Key:   "MEALIE_API_TOKEN",
			Value: "secret",
		},
	})
	require.NoError(t, err)
	require.Len(t, envResponse, 1)
	require.Equal(t, "MEALIE_API_TOKEN", envResponse[0].Key)

	restartResponse, err := client.RestartService(context.Background(), "service-123", true)
	require.NoError(t, err)
	require.Equal(t, "Service restart request queued.", restartResponse.Message)

	deleteResponse, err := client.DeleteService(context.Background(), "service-123", CoolifyDeleteServiceOptions{
		DeleteConfigurations:    true,
		DeleteVolumes:           true,
		DockerCleanup:           true,
		DeleteConnectedNetworks: true,
	})
	require.NoError(t, err)
	require.Equal(t, "Service deletion request queued.", deleteResponse.Message)
}

func TestCoolifyClientIncludesResponseBodyInHTTPStatusErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid compose payload", http.StatusUnprocessableEntity)
	}))
	defer server.Close()

	client, err := NewCoolifyClient(server.URL, "coolify-token", zerolog.Nop())
	require.NoError(t, err)

	_, err = client.CreateService(context.Background(), CoolifyCreateServiceRequest{
		Type:        "docker-compose",
		Name:        "mcp-mealie-u-123",
		ProjectUUID: "project-123",
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid compose payload")
}
