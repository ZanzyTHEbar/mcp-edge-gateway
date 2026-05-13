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

	rendered, err := renderMemoryTenant(Config{DockerNetwork: "example-network"}, tenant, service, map[string]string{
		"libsql-url":        "libsql://memory.example",
		"libsql-auth-token": "secret-token",
	})
	require.NoError(t, err)
	require.Contains(t, rendered.CreateRequest.DockerComposeRaw, "- mcp_tenant_network")
	require.Contains(t, rendered.CreateRequest.DockerComposeRaw, "name: example-network")
	require.NotContains(t, rendered.CreateRequest.DockerComposeRaw, "- coolify")
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

func TestRenderTenantsUsePinnedImageOverrides(t *testing.T) {
	t.Parallel()

	services := catalog.DefaultCatalogV1()
	tenant := TenantInstance{SubjectKey: "subject-a"}
	cfg := Config{
		DockerNetwork:           "example-network",
		MealieBaseURL:           "https://mealie.example.com",
		ActualServerURL:         "https://budget.example.com",
		TenantImageMealie:       "registry.example.com/mealie@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TenantImageActualBudget: "registry.example.com/actual@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TenantImageMemory:       "registry.example.com/memory@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}

	tenant.ServiceID = "mealie"
	tenant.TenantInstanceName = "mealie-subject-a"
	mealie, err := renderMealieTenant(cfg, tenant, services[0], map[string]string{"api-token": "token-value"})
	require.NoError(t, err)
	require.Contains(t, mealie.CreateRequest.DockerComposeRaw, "image: "+cfg.TenantImageMealie)
	require.Contains(t, mealie.CreateRequest.DockerComposeRaw, "name: example-network")

	tenant.ServiceID = "actualbudget"
	tenant.TenantInstanceName = "actualbudget-subject-a"
	actual, err := renderActualBudgetTenant(cfg, tenant, services[1], map[string]string{"actual-api-key": "api-key", "budget-sync-id": "sync-id"})
	require.NoError(t, err)
	require.Contains(t, actual.CreateRequest.DockerComposeRaw, "image: "+cfg.TenantImageActualBudget)
	require.Contains(t, actual.CreateRequest.DockerComposeRaw, "name: example-network")

	tenant.ServiceID = "memory"
	tenant.TenantInstanceName = "memory-subject-a"
	memory, err := renderMemoryTenant(cfg, tenant, services[2], map[string]string{"libsql-url": "libsql://memory.example", "libsql-auth-token": "secret-token"})
	require.NoError(t, err)
	require.Contains(t, memory.CreateRequest.DockerComposeRaw, "image: "+cfg.TenantImageMemory)
	require.Contains(t, memory.CreateRequest.DockerComposeRaw, "name: example-network")
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
