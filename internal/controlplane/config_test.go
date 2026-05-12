package controlplane

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfigValidateAllowsBaseControlPlaneConfig(t *testing.T) {
	t.Parallel()

	cfg := validBaseControlPlaneConfig()
	require.NoError(t, cfg.Validate())
}

func TestConfigValidateRejectsPartialDependencyConfig(t *testing.T) {
	t.Parallel()

	cfg := validBaseControlPlaneConfig()
	cfg.AuthentikIssuerURL = "https://auth.example.com/application/o/mcp-control-plane/"

	err := cfg.Validate()
	require.ErrorContains(t, err, "dependency configuration is partial")
}

func TestConfigValidateRejectsTenantRuntimeWithoutDependencyConfig(t *testing.T) {
	t.Parallel()

	cfg := validBaseControlPlaneConfig()
	cfg.CoolifyProjectUUID = "project-uuid"
	cfg.CoolifyEnvironmentUUID = "environment-uuid"
	cfg.CoolifyServerUUID = "server-uuid"
	cfg.CoolifyDestinationUUID = "destination-uuid"

	err := cfg.Validate()
	require.ErrorContains(t, err, "tenant runtime configuration requires full external dependency configuration")
}

func TestConfigValidateRejectsTenantRuntimeWithoutRenderPrereqs(t *testing.T) {
	t.Parallel()

	cfg := validTenantRuntimeControlPlaneConfig()
	cfg.MealieBaseURL = ""

	err := cfg.Validate()
	require.ErrorContains(t, err, "MCP_CONTROL_PLANE_MEALIE_BASE_URL")
}

func TestConfigValidateAllowsCompleteTenantRuntimeConfig(t *testing.T) {
	t.Parallel()

	cfg := validTenantRuntimeControlPlaneConfig()
	require.NoError(t, cfg.Validate())
}

func TestConfigValidateRequiresImmutableTenantImagesInProduction(t *testing.T) {
	t.Parallel()

	cfg := validTenantRuntimeControlPlaneConfig()
	cfg.PlatformEnv = "production"
	cfg.TenantImageMealie = "ghcr.io/example/mealie:latest"
	cfg.TenantImageActualBudget = "ghcr.io/example/actual@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.TenantImageMemory = "ghcr.io/example/memory@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	err := cfg.Validate()
	require.ErrorContains(t, err, "MCP_CONTROL_PLANE_TENANT_IMAGE_MEALIE must use an immutable digest")

	cfg.TenantImageMealie = "ghcr.io/example/mealie"
	err = cfg.Validate()
	require.ErrorContains(t, err, "MCP_CONTROL_PLANE_TENANT_IMAGE_MEALIE must use an immutable digest")

	cfg.TenantImageMealie = "ghcr.io/example/mealie:v1.2.3"
	err = cfg.Validate()
	require.ErrorContains(t, err, "MCP_CONTROL_PLANE_TENANT_IMAGE_MEALIE must use an immutable digest")

	cfg.TenantImageMealie = "ghcr.io/example/mealie@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	require.NoError(t, cfg.Validate())
}

func validBaseControlPlaneConfig() Config {
	return Config{
		DatabaseURL:         "file:data/mcp-platform.db",
		HTTPBindAddr:        ":8081",
		ReconcileInterval:   30 * time.Second,
		HealthcheckInterval: 30 * time.Second,
	}
}

func validTenantRuntimeControlPlaneConfig() Config {
	cfg := validBaseControlPlaneConfig()
	cfg.AuthentikIssuerURL = "https://auth.example.com/application/o/mcp-control-plane/"
	cfg.AuthentikClientID = "client-id"
	cfg.AuthentikClientSecretPath = "/platform/mcp-control-plane/authentik-client-secret"
	cfg.CoolifyAPIBaseURL = "https://coolify.example.com/api/v1"
	cfg.CoolifyAPITokenPath = "/platform/mcp-control-plane/coolify-api-token"
	cfg.InfisicalAPIBaseURL = "https://infisical.example.com/api"
	cfg.InfisicalProjectSlug = "dragonserver"
	cfg.InfisicalEnvSlug = "prod"
	cfg.InfisicalMachineClientID = "machine-client-id"
	cfg.InfisicalMachineClientSecretPath = "/platform/mcp-control-plane/infisical-machine-client-secret"
	cfg.CoolifyProjectUUID = "project-uuid"
	cfg.CoolifyEnvironmentUUID = "environment-uuid"
	cfg.CoolifyServerUUID = "server-uuid"
	cfg.CoolifyDestinationUUID = "destination-uuid"
	cfg.MealieBaseURL = "https://mealie.internal"
	cfg.ActualServerURL = "https://actual.internal"
	return cfg
}
