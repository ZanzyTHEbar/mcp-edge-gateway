package edge

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidateRequiresPersistentInputsOutsideFixtureMode(t *testing.T) {
	t.Parallel()

	cfg := Config{
		PublicBaseURL:      "https://mcp.example.com",
		AuthentikIssuerURL: "https://auth.example.com/application/o/mcp-edge/",
		AuthentikClientID:  "edge-client",
	}

	err := cfg.Validate()
	require.ErrorContains(t, err, "platform database url is required")

	cfg.PlatformDatabaseURL = "postgres://edge:edge@db.example.com:5432/mcp"
	err = cfg.Validate()
	require.ErrorContains(t, err, "session encryption key path is required")

	cfg.SessionEncryptionKeyPath = "/run/secrets/mcp-edge-session-key"
	require.NoError(t, cfg.Validate())
}

func TestConfigValidateAllowsFixtureModeWithoutPersistentInputs(t *testing.T) {
	t.Parallel()

	cfg := Config{
		PublicBaseURL:         "https://mcp.example.com",
		EnableFixtureMode:     true,
		FixtureOperatorToken:  "fixture-operator-token",
		FixtureAuthSubjectSub: "fixture-user",
	}

	require.NoError(t, cfg.Validate())
}
