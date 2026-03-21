package contracts

const (
	EnvPlatformEnv         = "MCP_PLATFORM_ENV"
	EnvPlatformLogLevel    = "MCP_PLATFORM_LOG_LEVEL"
	EnvPlatformDatabaseURL = "MCP_PLATFORM_DATABASE_URL"
)

const (
	EnvEdgeHTTPBindAddr              = "MCP_EDGE_HTTP_BIND_ADDR"
	EnvEdgePublicBaseURL             = "MCP_EDGE_PUBLIC_BASE_URL"
	EnvEdgeEnableFixtureMode         = "MCP_EDGE_ENABLE_FIXTURE_MODE"
	EnvEdgeAuthentikIssuerURL        = "MCP_EDGE_AUTHENTIK_ISSUER_URL"
	EnvEdgeAuthentikClientID         = "MCP_EDGE_AUTHENTIK_CLIENT_ID"
	EnvEdgeAuthentikClientSecretPath = "MCP_EDGE_AUTHENTIK_CLIENT_SECRET_PATH"
	EnvEdgeOperatorTokenPath         = "MCP_EDGE_OPERATOR_TOKEN_PATH"
	EnvEdgeSessionEncryptionKeyPath  = "MCP_EDGE_SESSION_ENCRYPTION_KEY_PATH"
	EnvEdgeCookieSecure              = "MCP_EDGE_COOKIE_SECURE"
)

const (
	EnvControlPlaneHTTPBindAddr                     = "MCP_CONTROL_PLANE_HTTP_BIND_ADDR"
	EnvControlPlaneReconcileInterval                = "MCP_CONTROL_PLANE_RECONCILE_INTERVAL"
	EnvControlPlaneHealthcheckInterval              = "MCP_CONTROL_PLANE_HEALTHCHECK_INTERVAL"
	EnvControlPlaneAuthentikIssuerURL               = "MCP_CONTROL_PLANE_AUTHENTIK_ISSUER_URL"
	EnvControlPlaneAuthentikClientID                = "MCP_CONTROL_PLANE_AUTHENTIK_CLIENT_ID"
	EnvControlPlaneAuthentikClientSecretPath        = "MCP_CONTROL_PLANE_AUTHENTIK_CLIENT_SECRET_PATH"
	EnvControlPlaneCoolifyAPIBaseURL                = "MCP_CONTROL_PLANE_COOLIFY_API_BASE_URL"
	EnvControlPlaneCoolifyAPITokenPath              = "MCP_CONTROL_PLANE_COOLIFY_API_TOKEN_PATH"
	EnvControlPlaneCoolifyProjectUUID               = "MCP_CONTROL_PLANE_COOLIFY_PROJECT_UUID"
	EnvControlPlaneCoolifyEnvironmentName           = "MCP_CONTROL_PLANE_COOLIFY_ENVIRONMENT_NAME"
	EnvControlPlaneCoolifyEnvironmentUUID           = "MCP_CONTROL_PLANE_COOLIFY_ENVIRONMENT_UUID"
	EnvControlPlaneCoolifyServerUUID                = "MCP_CONTROL_PLANE_COOLIFY_SERVER_UUID"
	EnvControlPlaneCoolifyDestinationUUID           = "MCP_CONTROL_PLANE_COOLIFY_DESTINATION_UUID"
	EnvControlPlaneInfisicalAPIBaseURL              = "MCP_CONTROL_PLANE_INFISICAL_API_BASE_URL"
	EnvControlPlaneInfisicalProjectSlug             = "MCP_CONTROL_PLANE_INFISICAL_PROJECT_SLUG"
	EnvControlPlaneInfisicalEnvSlug                 = "MCP_CONTROL_PLANE_INFISICAL_ENV_SLUG"
	EnvControlPlaneInfisicalMachineClientID         = "MCP_CONTROL_PLANE_INFISICAL_MACHINE_CLIENT_ID"
	EnvControlPlaneInfisicalMachineClientSecretPath = "MCP_CONTROL_PLANE_INFISICAL_MACHINE_CLIENT_SECRET_PATH"
	EnvControlPlaneMealieBaseURL                    = "MCP_CONTROL_PLANE_MEALIE_BASE_URL"
	EnvControlPlaneActualServerURL                  = "MCP_CONTROL_PLANE_ACTUAL_SERVER_URL"
	EnvControlPlaneTenantImageMealie                = "MCP_CONTROL_PLANE_TENANT_IMAGE_MEALIE"
	EnvControlPlaneTenantImageActualBudget          = "MCP_CONTROL_PLANE_TENANT_IMAGE_ACTUALBUDGET"
	EnvControlPlaneTenantImageMemory                = "MCP_CONTROL_PLANE_TENANT_IMAGE_MEMORY"
)
