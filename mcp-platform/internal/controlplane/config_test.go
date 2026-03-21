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

func validBaseControlPlaneConfig() Config {
	return Config{
		DatabaseURL:         "postgres://user:pass@db.example.com:5432/mcp",
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
