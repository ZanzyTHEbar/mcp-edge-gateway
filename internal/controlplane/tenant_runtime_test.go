package controlplane

import (
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"

	"github.com/stretchr/testify/require"
)

func TestShouldRequeueDelete(t *testing.T) {
	t.Parallel()

	require.True(t, shouldRequeueDelete(nil))

	recent := time.Now().UTC().Add(-(deleteRequeueInterval / 2))
	require.False(t, shouldRequeueDelete(&recent))

	stale := time.Now().UTC().Add(-(deleteRequeueInterval + time.Second))
	require.True(t, shouldRequeueDelete(&stale))
}

func TestRenderMemoryTenantUsesSSEContract(t *testing.T) {
	t.Parallel()

	service := catalog.DefaultCatalogV1()[2]
	tenant := TenantInstance{
		ServiceID:          service.ServiceID,
		SubjectKey:         "subject-a",
		TenantInstanceName: "memory-subject-a",
	}

	rendered, err := renderMemoryTenant(Config{}, tenant, service, map[string]string{
		"libsql-url":        "libsql://memory.example",
		"libsql-auth-token": "secret-token",
	})
	require.NoError(t, err)
	require.NotContains(t, rendered.CreateRequest.DockerComposeRaw, "stdio")
	require.Contains(t, rendered.CreateRequest.DockerComposeRaw, "TRANSPORT: ${TRANSPORT}")
	require.Contains(t, rendered.CreateRequest.DockerComposeRaw, "SSE_ENDPOINT: ${SSE_ENDPOINT}")
	require.Equal(t, "http://"+domain.BuildTenantInstanceName(service.ServiceID, tenant.SubjectKey)+":8090/sse", rendered.UpstreamURL)

	envs := make(map[string]string, len(rendered.EnvVars))
	for _, env := range rendered.EnvVars {
		envs[env.Key] = env.Value
	}
	require.Equal(t, "sse", envs["TRANSPORT"])
	require.Equal(t, "/sse", envs["SSE_ENDPOINT"])
	require.Equal(t, "libsql://memory.example", envs["LIBSQL_URL"])
	require.Equal(t, "secret-token", envs["LIBSQL_AUTH_TOKEN"])
}

func TestRenderMealieTenantUsesLocalDefaultImage(t *testing.T) {
	t.Parallel()

	service := catalog.DefaultCatalogV1()[0]
	tenant := TenantInstance{
		ServiceID:          service.ServiceID,
		SubjectKey:         "subject-a",
		TenantInstanceName: "mealie-subject-a",
	}

	rendered, err := renderMealieTenant(Config{MealieBaseURL: "https://mealie.example.com"}, tenant, service, map[string]string{
		"api-token": "token-value",
	})
	require.NoError(t, err)
	require.Contains(t, rendered.CreateRequest.DockerComposeRaw, "image: mealie-mcp:latest")
}

func TestRenderActualBudgetTenantUsesLocalDefaultImage(t *testing.T) {
	t.Parallel()

	service := catalog.DefaultCatalogV1()[1]
	tenant := TenantInstance{
		ServiceID:          service.ServiceID,
		SubjectKey:         "subject-a",
		TenantInstanceName: "actualbudget-subject-a",
	}

	rendered, err := renderActualBudgetTenant(Config{ActualServerURL: "https://budget.example.com"}, tenant, service, map[string]string{
		"actual-api-key": "api-key",
		"budget-sync-id": "sync-id",
	})
	require.NoError(t, err)
	require.Contains(t, rendered.CreateRequest.DockerComposeRaw, "image: actual-mcp-server:latest")
}
