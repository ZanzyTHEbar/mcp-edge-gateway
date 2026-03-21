package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type CoolifyClient struct {
	logger     zerolog.Logger
	baseURL    string
	apiToken   string
	httpClient *http.Client
}

type CoolifyURL struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type CoolifyCreateServiceRequest struct {
	Type                string       `json:"type"`
	Name                string       `json:"name"`
	Description         string       `json:"description,omitempty"`
	ProjectUUID         string       `json:"project_uuid"`
	EnvironmentName     string       `json:"environment_name,omitempty"`
	EnvironmentUUID     string       `json:"environment_uuid,omitempty"`
	ServerUUID          string       `json:"server_uuid,omitempty"`
	DestinationUUID     string       `json:"destination_uuid,omitempty"`
	InstantDeploy       bool         `json:"instant_deploy"`
	DockerComposeRaw    string       `json:"docker_compose_raw,omitempty"`
	URLs                []CoolifyURL `json:"urls,omitempty"`
	ForceDomainOverride bool         `json:"force_domain_override,omitempty"`
}

type CoolifyUpdateServiceRequest struct {
	Name                string       `json:"name,omitempty"`
	Description         string       `json:"description,omitempty"`
	ProjectUUID         string       `json:"project_uuid,omitempty"`
	EnvironmentName     string       `json:"environment_name,omitempty"`
	EnvironmentUUID     string       `json:"environment_uuid,omitempty"`
	ServerUUID          string       `json:"server_uuid,omitempty"`
	DestinationUUID     string       `json:"destination_uuid,omitempty"`
	InstantDeploy       bool         `json:"instant_deploy,omitempty"`
	DockerComposeRaw    string       `json:"docker_compose_raw,omitempty"`
	URLs                []CoolifyURL `json:"urls,omitempty"`
	ForceDomainOverride bool         `json:"force_domain_override,omitempty"`
}

type CoolifyService struct {
	UUID             string `json:"uuid"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	DockerComposeRaw string `json:"docker_compose_raw"`
}

type CoolifyCreateServiceResponse struct {
	UUID    string   `json:"uuid"`
	Domains []string `json:"domains"`
}

type CoolifyEnvVar struct {
	UUID        string `json:"uuid,omitempty"`
	Key         string `json:"key"`
	Value       string `json:"value"`
	IsPreview   bool   `json:"is_preview,omitempty"`
	IsLiteral   bool   `json:"is_literal,omitempty"`
	IsMultiline bool   `json:"is_multiline,omitempty"`
	IsShownOnce bool   `json:"is_shown_once,omitempty"`
}

type CoolifyQueuedActionResponse struct {
	Message        string `json:"message"`
	DeploymentUUID string `json:"deployment_uuid,omitempty"`
}

type CoolifyDeleteServiceOptions struct {
	DeleteConfigurations    bool
	DeleteVolumes           bool
	DockerCleanup           bool
	DeleteConnectedNetworks bool
}

func NewCoolifyClient(baseURL string, apiToken string, logger zerolog.Logger) (*CoolifyClient, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("coolify api base url is required")
	}
	if strings.TrimSpace(apiToken) == "" {
		return nil, fmt.Errorf("coolify api token is required")
	}

	return &CoolifyClient{
		logger:   logger,
		baseURL:  strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiToken: strings.TrimSpace(apiToken),
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}, nil
}

func NewCoolifyClientFromConfig(ctx context.Context, cfg Config, secrets SecretResolver, logger zerolog.Logger) (*CoolifyClient, error) {
	if secrets == nil {
		return nil, fmt.Errorf("secret resolver is required")
	}
	apiToken, err := secrets.ResolveSecretReference(ctx, cfg.CoolifyAPITokenPath)
	if err != nil {
		return nil, err
	}
	return NewCoolifyClient(cfg.CoolifyAPIBaseURL, apiToken, logger)
}

func (c *CoolifyClient) CreateService(ctx context.Context, requestBody CoolifyCreateServiceRequest) (CoolifyCreateServiceResponse, error) {
	var response CoolifyCreateServiceResponse
	err := c.doJSON(ctx, http.MethodPost, c.baseURL+"/services", requestBody, &response)
	return response, err
}

func (c *CoolifyClient) GetService(ctx context.Context, serviceUUID string) (CoolifyService, error) {
	var response CoolifyService
	err := c.doJSON(ctx, http.MethodGet, c.baseURL+"/services/"+url.PathEscape(serviceUUID), nil, &response)
	return response, err
}

func (c *CoolifyClient) UpdateService(ctx context.Context, serviceUUID string, requestBody CoolifyUpdateServiceRequest) error {
	return c.doJSON(ctx, http.MethodPatch, c.baseURL+"/services/"+url.PathEscape(serviceUUID), requestBody, nil)
}

func (c *CoolifyClient) ListServiceEnvs(ctx context.Context, serviceUUID string) ([]CoolifyEnvVar, error) {
	var response []CoolifyEnvVar
	err := c.doJSON(ctx, http.MethodGet, c.baseURL+"/services/"+url.PathEscape(serviceUUID)+"/envs", nil, &response)
	return response, err
}

func (c *CoolifyClient) UpdateServiceEnvsBulk(ctx context.Context, serviceUUID string, envs []CoolifyEnvVar) ([]CoolifyEnvVar, error) {
	requestBody := map[string]any{
		"data": envs,
	}
	var response []CoolifyEnvVar
	err := c.doJSON(ctx, http.MethodPatch, c.baseURL+"/services/"+url.PathEscape(serviceUUID)+"/envs/bulk", requestBody, &response)
	return response, err
}

func (c *CoolifyClient) RestartService(ctx context.Context, serviceUUID string, latest bool) (CoolifyQueuedActionResponse, error) {
	queryValues := url.Values{}
	if latest {
		queryValues.Set("latest", "true")
	}
	requestURL := c.baseURL + "/services/" + url.PathEscape(serviceUUID) + "/restart"
	if encoded := queryValues.Encode(); encoded != "" {
		requestURL += "?" + encoded
	}

	var response CoolifyQueuedActionResponse
	err := c.doJSON(ctx, http.MethodPost, requestURL, nil, &response)
	return response, err
}

func (c *CoolifyClient) StartService(ctx context.Context, serviceUUID string) (CoolifyQueuedActionResponse, error) {
	var response CoolifyQueuedActionResponse
	err := c.doJSON(ctx, http.MethodPost, c.baseURL+"/services/"+url.PathEscape(serviceUUID)+"/start", nil, &response)
	return response, err
}

func (c *CoolifyClient) StopService(ctx context.Context, serviceUUID string, dockerCleanup bool) (CoolifyQueuedActionResponse, error) {
	queryValues := url.Values{}
	queryValues.Set("docker_cleanup", boolQueryValue(dockerCleanup, true))
	requestURL := c.baseURL + "/services/" + url.PathEscape(serviceUUID) + "/stop?" + queryValues.Encode()

	var response CoolifyQueuedActionResponse
	err := c.doJSON(ctx, http.MethodPost, requestURL, nil, &response)
	return response, err
}

func (c *CoolifyClient) DeleteService(ctx context.Context, serviceUUID string, options CoolifyDeleteServiceOptions) (CoolifyQueuedActionResponse, error) {
	queryValues := url.Values{}
	queryValues.Set("delete_configurations", boolQueryValue(options.DeleteConfigurations, true))
	queryValues.Set("delete_volumes", boolQueryValue(options.DeleteVolumes, true))
	queryValues.Set("docker_cleanup", boolQueryValue(options.DockerCleanup, true))
	queryValues.Set("delete_connected_networks", boolQueryValue(options.DeleteConnectedNetworks, true))

	requestURL := c.baseURL + "/services/" + url.PathEscape(serviceUUID) + "?" + queryValues.Encode()
	var response CoolifyQueuedActionResponse
	err := c.doJSON(ctx, http.MethodDelete, requestURL, nil, &response)
	return response, err
}

func (c *CoolifyClient) doJSON(ctx context.Context, method string, requestURL string, requestBody any, responseBody any) error {
	var bodyBytes []byte
	if requestBody != nil {
		marshaled, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("marshal coolify request body: %w", err)
		}
		bodyBytes = marshaled
	}

	request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("build coolify request %s %s: %w", method, requestURL, err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiToken)
	request.Header.Set("Content-Type", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("perform coolify request %s %s: %w", method, requestURL, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return newHTTPStatusError(method, requestURL, response)
	}
	if responseBody == nil {
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(responseBody); err != nil {
		return fmt.Errorf("decode coolify response %s %s: %w", method, requestURL, err)
	}
	return nil
}

func boolQueryValue(value bool, defaultValue bool) string {
	if !value && defaultValue {
		return "false"
	}
	if value {
		return "true"
	}
	return "false"
}
