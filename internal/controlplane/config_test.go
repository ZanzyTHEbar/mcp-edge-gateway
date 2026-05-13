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

func TestConfigValidateRejectsInvalidDockerNetworkName(t *testing.T) {
	t.Parallel()

	for _, network := range []string{"", "bad network", "bad:network", "#bad", "_bad", "bad\nnetwork"} {
		cfg := validBaseControlPlaneConfig()
		cfg.DockerNetwork = network

		err := cfg.Validate()
		require.ErrorContains(t, err, "MCP_DOCKER_NETWORK")
	}

	cfg := validBaseControlPlaneConfig()
	cfg.DockerNetwork = "example_network-1.prod"
	require.NoError(t, cfg.Validate())
}

func TestConfigValidateAllowsCompleteTenantRuntimeConfig(t *testing.T) {
	t.Parallel()

	cfg := validTenantRuntimeControlPlaneConfig()
	require.NoError(t, cfg.Validate())
}

func TestConfigValidatePinnedTenantImageModeRequiresImmutableDigests(t *testing.T) {
	t.Parallel()

	cfg := validTenantRuntimeControlPlaneConfig()
	cfg.PlatformEnv = "production"
	cfg.TenantImageMode = "pinned"
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

func TestConfigValidatePinnedTenantImageModeRequiresDigestsOutsideProduction(t *testing.T) {
	t.Parallel()

	cfg := validTenantRuntimeControlPlaneConfig()
	cfg.PlatformEnv = "development"
	cfg.TenantImageMode = "pinned"
	cfg.TenantImageMealie = "mealie-mcp:latest"
	cfg.TenantImageActualBudget = "actual-mcp-server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.TenantImageMemory = "mcp-memory-libsql-go@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	err := cfg.Validate()
	require.ErrorContains(t, err, "MCP_CONTROL_PLANE_TENANT_IMAGE_MEALIE must use an immutable digest")
}

func TestConfigValidateAllowsLocalTenantImagesInProduction(t *testing.T) {
	t.Parallel()

	cfg := validTenantRuntimeControlPlaneConfig()
	cfg.PlatformEnv = "production"
	cfg.TenantImageMode = "local"
	cfg.TenantImageMealie = "example-service-a:latest"
	cfg.TenantImageActualBudget = "actual-mcp-server:latest"
	cfg.TenantImageMemory = "example-service-c:latest"

	require.NoError(t, cfg.Validate())
}

func TestConfigValidateRejectsUnknownTenantImageMode(t *testing.T) {
	t.Parallel()

	cfg := validTenantRuntimeControlPlaneConfig()
	cfg.TenantImageMode = "remote"

	err := cfg.Validate()
	require.ErrorContains(t, err, "MCP_CONTROL_PLANE_TENANT_IMAGE_MODE")
}

func validBaseControlPlaneConfig() Config {
	return Config{
		DatabaseURL:         "file:data/mcp-platform.db",
		DockerNetwork:       "coolify",
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
	cfg.InfisicalProjectSlug = "example-project"
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
