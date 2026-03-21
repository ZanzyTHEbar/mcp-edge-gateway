package controlplane

import (
	"fmt"
	"strings"
	"time"

	"dragonserver/mcp-platform/internal/contracts"

	"github.com/spf13/viper"
)

type Config struct {
	PlatformEnv                      string
	LogLevel                         string
	DatabaseURL                      string
	HTTPBindAddr                     string
	ReconcileInterval                time.Duration
	HealthcheckInterval              time.Duration
	AuthentikIssuerURL               string
	AuthentikClientID                string
	AuthentikClientSecretPath        string
	CoolifyAPIBaseURL                string
	CoolifyAPITokenPath              string
	CoolifyProjectUUID               string
	CoolifyEnvironmentName           string
	CoolifyEnvironmentUUID           string
	CoolifyServerUUID                string
	CoolifyDestinationUUID           string
	InfisicalAPIBaseURL              string
	InfisicalProjectSlug             string
	InfisicalEnvSlug                 string
	InfisicalMachineClientID         string
	InfisicalMachineClientSecretPath string
	MealieBaseURL                    string
	ActualServerURL                  string
	TenantImageMealie                string
	TenantImageActualBudget          string
	TenantImageMemory                string
}

func LoadConfig() (Config, error) {
	viper.AutomaticEnv()
	viper.SetDefault(contracts.EnvPlatformEnv, "production")
	viper.SetDefault(contracts.EnvPlatformLogLevel, "info")
	viper.SetDefault(contracts.EnvControlPlaneHTTPBindAddr, ":8081")
	viper.SetDefault(contracts.EnvControlPlaneReconcileInterval, "30s")
	viper.SetDefault(contracts.EnvControlPlaneHealthcheckInterval, "30s")

	reconcileInterval, err := parseDurationEnv(contracts.EnvControlPlaneReconcileInterval)
	if err != nil {
		return Config{}, err
	}

	healthcheckInterval, err := parseDurationEnv(contracts.EnvControlPlaneHealthcheckInterval)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		PlatformEnv:                      strings.TrimSpace(viper.GetString(contracts.EnvPlatformEnv)),
		LogLevel:                         strings.TrimSpace(viper.GetString(contracts.EnvPlatformLogLevel)),
		DatabaseURL:                      strings.TrimSpace(viper.GetString(contracts.EnvPlatformDatabaseURL)),
		HTTPBindAddr:                     strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneHTTPBindAddr)),
		ReconcileInterval:                reconcileInterval,
		HealthcheckInterval:              healthcheckInterval,
		AuthentikIssuerURL:               strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneAuthentikIssuerURL)),
		AuthentikClientID:                strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneAuthentikClientID)),
		AuthentikClientSecretPath:        strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneAuthentikClientSecretPath)),
		CoolifyAPIBaseURL:                strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneCoolifyAPIBaseURL)),
		CoolifyAPITokenPath:              strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneCoolifyAPITokenPath)),
		CoolifyProjectUUID:               strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneCoolifyProjectUUID)),
		CoolifyEnvironmentName:           strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneCoolifyEnvironmentName)),
		CoolifyEnvironmentUUID:           strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneCoolifyEnvironmentUUID)),
		CoolifyServerUUID:                strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneCoolifyServerUUID)),
		CoolifyDestinationUUID:           strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneCoolifyDestinationUUID)),
		InfisicalAPIBaseURL:              strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneInfisicalAPIBaseURL)),
		InfisicalProjectSlug:             strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneInfisicalProjectSlug)),
		InfisicalEnvSlug:                 strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneInfisicalEnvSlug)),
		InfisicalMachineClientID:         strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneInfisicalMachineClientID)),
		InfisicalMachineClientSecretPath: strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneInfisicalMachineClientSecretPath)),
		MealieBaseURL:                    strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneMealieBaseURL)),
		ActualServerURL:                  strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneActualServerURL)),
		TenantImageMealie:                strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneTenantImageMealie)),
		TenantImageActualBudget:          strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneTenantImageActualBudget)),
		TenantImageMemory:                strings.TrimSpace(viper.GetString(contracts.EnvControlPlaneTenantImageMemory)),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("%s is required", contracts.EnvPlatformDatabaseURL)
	}
	if c.HTTPBindAddr == "" {
		return fmt.Errorf("%s is required", contracts.EnvControlPlaneHTTPBindAddr)
	}
	if c.ReconcileInterval <= 0 {
		return fmt.Errorf("%s must be greater than zero", contracts.EnvControlPlaneReconcileInterval)
	}
	if c.HealthcheckInterval <= 0 {
		return fmt.Errorf("%s must be greater than zero", contracts.EnvControlPlaneHealthcheckInterval)
	}
	if err := c.validateDependencyConfig(); err != nil {
		return err
	}
	if err := c.validateTenantRuntimeConfig(); err != nil {
		return err
	}
	return nil
}

func (c Config) validateDependencyConfig() error {
	dependencyFields := []struct {
		envKey string
		value  string
	}{
		{envKey: contracts.EnvControlPlaneAuthentikIssuerURL, value: c.AuthentikIssuerURL},
		{envKey: contracts.EnvControlPlaneAuthentikClientID, value: c.AuthentikClientID},
		{envKey: contracts.EnvControlPlaneAuthentikClientSecretPath, value: c.AuthentikClientSecretPath},
		{envKey: contracts.EnvControlPlaneCoolifyAPIBaseURL, value: c.CoolifyAPIBaseURL},
		{envKey: contracts.EnvControlPlaneCoolifyAPITokenPath, value: c.CoolifyAPITokenPath},
		{envKey: contracts.EnvControlPlaneInfisicalAPIBaseURL, value: c.InfisicalAPIBaseURL},
		{envKey: contracts.EnvControlPlaneInfisicalProjectSlug, value: c.InfisicalProjectSlug},
		{envKey: contracts.EnvControlPlaneInfisicalEnvSlug, value: c.InfisicalEnvSlug},
		{envKey: contracts.EnvControlPlaneInfisicalMachineClientID, value: c.InfisicalMachineClientID},
		{envKey: contracts.EnvControlPlaneInfisicalMachineClientSecretPath, value: c.InfisicalMachineClientSecretPath},
	}

	anySet := false
	missing := make([]string, 0)
	for _, field := range dependencyFields {
		if field.value != "" {
			anySet = true
			continue
		}
		missing = append(missing, field.envKey)
	}
	if !anySet || len(missing) == 0 {
		return nil
	}

	return fmt.Errorf(
		"control-plane dependency configuration is partial; missing %s",
		strings.Join(missing, ", "),
	)
}

func (c Config) validateTenantRuntimeConfig() error {
	runtimeFieldsSet := c.CoolifyProjectUUID != "" ||
		c.CoolifyEnvironmentName != "" ||
		c.CoolifyEnvironmentUUID != "" ||
		c.CoolifyServerUUID != "" ||
		c.CoolifyDestinationUUID != ""
	if !runtimeFieldsSet {
		return nil
	}

	if !c.HasDependencyConfig() {
		return fmt.Errorf("tenant runtime configuration requires full external dependency configuration")
	}
	if c.CoolifyProjectUUID == "" {
		return fmt.Errorf("%s is required when tenant runtime is enabled", contracts.EnvControlPlaneCoolifyProjectUUID)
	}
	if c.CoolifyEnvironmentName == "" && c.CoolifyEnvironmentUUID == "" {
		return fmt.Errorf(
			"%s or %s is required when tenant runtime is enabled",
			contracts.EnvControlPlaneCoolifyEnvironmentName,
			contracts.EnvControlPlaneCoolifyEnvironmentUUID,
		)
	}
	if c.CoolifyServerUUID == "" {
		return fmt.Errorf("%s is required when tenant runtime is enabled", contracts.EnvControlPlaneCoolifyServerUUID)
	}
	if c.CoolifyDestinationUUID == "" {
		return fmt.Errorf("%s is required when tenant runtime is enabled", contracts.EnvControlPlaneCoolifyDestinationUUID)
	}
	if c.MealieBaseURL == "" {
		return fmt.Errorf("%s is required when tenant runtime is enabled", contracts.EnvControlPlaneMealieBaseURL)
	}
	if c.ActualServerURL == "" {
		return fmt.Errorf("%s is required when tenant runtime is enabled", contracts.EnvControlPlaneActualServerURL)
	}

	return nil
}

func (c Config) HasDependencyConfig() bool {
	return c.AuthentikIssuerURL != "" &&
		c.AuthentikClientID != "" &&
		c.AuthentikClientSecretPath != "" &&
		c.CoolifyAPIBaseURL != "" &&
		c.CoolifyAPITokenPath != "" &&
		c.InfisicalAPIBaseURL != "" &&
		c.InfisicalProjectSlug != "" &&
		c.InfisicalEnvSlug != "" &&
		c.InfisicalMachineClientID != "" &&
		c.InfisicalMachineClientSecretPath != ""
}

func (c Config) HasTenantRuntimeConfig() bool {
	return c.CoolifyProjectUUID != "" &&
		(c.CoolifyEnvironmentName != "" || c.CoolifyEnvironmentUUID != "") &&
		c.CoolifyServerUUID != "" &&
		c.CoolifyDestinationUUID != ""
}

func parseDurationEnv(envKey string) (time.Duration, error) {
	rawValue := strings.TrimSpace(viper.GetString(envKey))
	parsedValue, err := time.ParseDuration(rawValue)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", envKey, err)
	}
	return parsedValue, nil
}
