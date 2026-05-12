package edge

import (
	"fmt"
	"strings"

	"dragonserver/mcp-platform/internal/contracts"

	"github.com/spf13/viper"
)

const (
	envEdgeFixtureUpstreamMealieURL       = "MCP_EDGE_FIXTURE_UPSTREAM_MEALIE_URL"
	envEdgeFixtureUpstreamActualBudgetURL = "MCP_EDGE_FIXTURE_UPSTREAM_ACTUALBUDGET_URL"
	envEdgeFixtureUpstreamMemoryURL       = "MCP_EDGE_FIXTURE_UPSTREAM_MEMORY_URL"
	envEdgeFixtureInsecureSkipVerify      = "MCP_EDGE_FIXTURE_INSECURE_SKIP_VERIFY"
	envEdgeFixtureAuthentikClientSecret   = "MCP_EDGE_FIXTURE_AUTHENTIK_CLIENT_SECRET"
	envEdgeFixtureAuthSubjectSub          = "MCP_EDGE_FIXTURE_AUTH_SUBJECT_SUB"
	envEdgeFixtureAuthSubjectEmail        = "MCP_EDGE_FIXTURE_AUTH_SUBJECT_EMAIL"
	envEdgeFixtureAuthSubjectName         = "MCP_EDGE_FIXTURE_AUTH_SUBJECT_NAME"
	envEdgeFixtureAuthPreferredUsername   = "MCP_EDGE_FIXTURE_AUTH_PREFERRED_USERNAME"
	envEdgeFixtureAuthGroups              = "MCP_EDGE_FIXTURE_AUTH_GROUPS"
	envEdgeFixtureOperatorToken           = "MCP_EDGE_FIXTURE_OPERATOR_TOKEN"
)

type Config struct {
	PlatformEnv                    string
	LogLevel                       string
	PlatformDatabaseURL            string
	HTTPBindAddr                   string
	PublicBaseURL                  string
	EnableFixtureMode              bool
	AuthentikIssuerURL             string
	AuthentikClientID              string
	AuthentikClientSecretPath      string
	OperatorTokenPath              string
	SessionEncryptionKeyPath       string
	CookieSecure                   bool
	FixtureUpstreamMealieURL       string
	FixtureUpstreamActualBudgetURL string
	FixtureUpstreamMemoryURL       string
	FixtureInsecureSkipVerify      bool
	FixtureAuthentikClientSecret   string
	FixtureAuthSubjectSub          string
	FixtureAuthSubjectEmail        string
	FixtureAuthSubjectName         string
	FixtureAuthPreferredUsername   string
	FixtureAuthGroups              []string
	FixtureOperatorToken           string
}

func LoadConfig() Config {
	viper.AutomaticEnv()
	viper.SetDefault(contracts.EnvPlatformEnv, "development")
	viper.SetDefault(contracts.EnvPlatformLogLevel, "info")
	viper.SetDefault(contracts.EnvEdgeHTTPBindAddr, ":8080")
	viper.SetDefault(contracts.EnvEdgePublicBaseURL, "http://localhost:8080")
	viper.SetDefault(contracts.EnvEdgeCookieSecure, true)

	return Config{
		PlatformEnv:                    strings.TrimSpace(viper.GetString(contracts.EnvPlatformEnv)),
		LogLevel:                       strings.TrimSpace(viper.GetString(contracts.EnvPlatformLogLevel)),
		PlatformDatabaseURL:            strings.TrimSpace(viper.GetString(contracts.EnvPlatformDatabaseURL)),
		HTTPBindAddr:                   strings.TrimSpace(viper.GetString(contracts.EnvEdgeHTTPBindAddr)),
		PublicBaseURL:                  strings.TrimSpace(viper.GetString(contracts.EnvEdgePublicBaseURL)),
		EnableFixtureMode:              viper.GetBool(contracts.EnvEdgeEnableFixtureMode),
		AuthentikIssuerURL:             strings.TrimSpace(viper.GetString(contracts.EnvEdgeAuthentikIssuerURL)),
		AuthentikClientID:              strings.TrimSpace(viper.GetString(contracts.EnvEdgeAuthentikClientID)),
		AuthentikClientSecretPath:      strings.TrimSpace(viper.GetString(contracts.EnvEdgeAuthentikClientSecretPath)),
		OperatorTokenPath:              strings.TrimSpace(viper.GetString(contracts.EnvEdgeOperatorTokenPath)),
		SessionEncryptionKeyPath:       strings.TrimSpace(viper.GetString(contracts.EnvEdgeSessionEncryptionKeyPath)),
		CookieSecure:                   viper.GetBool(contracts.EnvEdgeCookieSecure),
		FixtureUpstreamMealieURL:       strings.TrimSpace(viper.GetString(envEdgeFixtureUpstreamMealieURL)),
		FixtureUpstreamActualBudgetURL: strings.TrimSpace(viper.GetString(envEdgeFixtureUpstreamActualBudgetURL)),
		FixtureUpstreamMemoryURL:       strings.TrimSpace(viper.GetString(envEdgeFixtureUpstreamMemoryURL)),
		FixtureInsecureSkipVerify:      viper.GetBool(envEdgeFixtureInsecureSkipVerify),
		FixtureAuthentikClientSecret:   strings.TrimSpace(viper.GetString(envEdgeFixtureAuthentikClientSecret)),
		FixtureAuthSubjectSub:          strings.TrimSpace(viper.GetString(envEdgeFixtureAuthSubjectSub)),
		FixtureAuthSubjectEmail:        strings.TrimSpace(viper.GetString(envEdgeFixtureAuthSubjectEmail)),
		FixtureAuthSubjectName:         strings.TrimSpace(viper.GetString(envEdgeFixtureAuthSubjectName)),
		FixtureAuthPreferredUsername:   strings.TrimSpace(viper.GetString(envEdgeFixtureAuthPreferredUsername)),
		FixtureAuthGroups:              splitCommaSeparated(viper.GetString(envEdgeFixtureAuthGroups)),
		FixtureOperatorToken:           strings.TrimSpace(viper.GetString(envEdgeFixtureOperatorToken)),
	}
}

func (c Config) HasOIDCConfig() bool {
	return strings.TrimSpace(c.AuthentikIssuerURL) != "" && strings.TrimSpace(c.AuthentikClientID) != ""
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.PublicBaseURL) == "" {
		return fmt.Errorf("mcp-edge public base url is required")
	}
	if c.EnableFixtureMode && strings.EqualFold(strings.TrimSpace(c.PlatformEnv), "production") {
		return fmt.Errorf("fixture mode cannot be enabled in production")
	}
	if !c.HasOIDCConfig() && !c.EnableFixtureMode {
		return fmt.Errorf("mcp-edge requires Authentik OIDC configuration unless fixture mode is explicitly enabled")
	}
	if !c.EnableFixtureMode && strings.TrimSpace(c.PlatformDatabaseURL) == "" {
		return fmt.Errorf("mcp-edge platform database url is required outside fixture mode")
	}
	if !c.EnableFixtureMode && strings.TrimSpace(c.SessionEncryptionKeyPath) == "" {
		return fmt.Errorf("mcp-edge session encryption key path is required outside fixture mode")
	}
	if c.FixtureInsecureSkipVerify && !c.EnableFixtureMode {
		return fmt.Errorf("fixture insecure skip verify requires fixture mode")
	}
	if !c.EnableFixtureMode && c.usesFixtureInputs() {
		return fmt.Errorf("fixture inputs are configured but fixture mode is disabled")
	}
	return nil
}

func (c Config) usesFixtureInputs() bool {
	return c.FixtureUpstreamMealieURL != "" ||
		c.FixtureUpstreamActualBudgetURL != "" ||
		c.FixtureUpstreamMemoryURL != "" ||
		c.FixtureInsecureSkipVerify ||
		c.FixtureAuthentikClientSecret != "" ||
		c.FixtureAuthSubjectSub != "" ||
		c.FixtureAuthSubjectEmail != "" ||
		c.FixtureAuthSubjectName != "" ||
		c.FixtureAuthPreferredUsername != "" ||
		len(c.FixtureAuthGroups) > 0 ||
		c.FixtureOperatorToken != ""
}

func splitCommaSeparated(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	return values
}
