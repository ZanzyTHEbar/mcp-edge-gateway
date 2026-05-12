package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type InfisicalClient struct {
	logger              zerolog.Logger
	baseURL             string
	projectSlug         string
	environmentSlug     string
	machineClientID     string
	machineClientSecret string
	httpClient          *http.Client

	mu             sync.Mutex
	accessToken    string
	accessTokenExp time.Time
	projectID      string
}

type InfisicalSecret struct {
	SecretKey   string
	SecretValue string
	SecretPath  string
}

type infisicalLoginRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type infisicalLoginResponse struct {
	AccessToken string  `json:"accessToken"`
	ExpiresIn   float64 `json:"expiresIn"`
	TokenType   string  `json:"tokenType"`
}

type infisicalProjectResponse struct {
	ID string `json:"id"`
}

type infisicalSecretsResponse struct {
	Secrets []struct {
		SecretKey   string `json:"secretKey"`
		SecretValue string `json:"secretValue"`
		SecretPath  string `json:"secretPath"`
	} `json:"secrets"`
}

func NewInfisicalClient(cfg Config, logger zerolog.Logger) (*InfisicalClient, error) {
	if strings.TrimSpace(cfg.InfisicalAPIBaseURL) == "" {
		return nil, fmt.Errorf("infisical api base url is required")
	}
	if strings.TrimSpace(cfg.InfisicalProjectSlug) == "" {
		return nil, fmt.Errorf("infisical project slug is required")
	}
	if strings.TrimSpace(cfg.InfisicalEnvSlug) == "" {
		return nil, fmt.Errorf("infisical env slug is required")
	}
	if strings.TrimSpace(cfg.InfisicalMachineClientID) == "" {
		return nil, fmt.Errorf("infisical machine client id is required")
	}

	machineClientSecret, err := ReadSecretFromFile(cfg.InfisicalMachineClientSecretPath)
	if err != nil {
		return nil, err
	}

	return &InfisicalClient{
		logger:              logger,
		baseURL:             strings.TrimRight(strings.TrimSpace(cfg.InfisicalAPIBaseURL), "/"),
		projectSlug:         strings.TrimSpace(cfg.InfisicalProjectSlug),
		environmentSlug:     strings.TrimSpace(cfg.InfisicalEnvSlug),
		machineClientID:     strings.TrimSpace(cfg.InfisicalMachineClientID),
		machineClientSecret: machineClientSecret,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}, nil
}

func (c *InfisicalClient) ResolveSecretReference(ctx context.Context, reference string) (string, error) {
	if !IsInfisicalSecretReference(reference) || localFileExists(reference) {
		return ReadSecretFromFile(reference)
	}

	secretPath, secretKey, err := SplitInfisicalSecretReference(reference)
	if err != nil {
		return "", err
	}

	secrets, err := c.ListSecrets(ctx, secretPath)
	if err != nil {
		return "", err
	}
	for _, secret := range secrets {
		if secret.SecretKey == secretKey {
			return secret.SecretValue, nil
		}
	}

	return "", fmt.Errorf("infisical secret %q not found", reference)
}

func (c *InfisicalClient) ListSecrets(ctx context.Context, secretPath string) ([]InfisicalSecret, error) {
	projectID, err := c.ensureProjectID(ctx)
	if err != nil {
		return nil, err
	}

	queryValues := url.Values{}
	queryValues.Set("projectId", projectID)
	queryValues.Set("environment", c.environmentSlug)
	queryValues.Set("secretPath", secretPath)
	queryValues.Set("viewSecretValue", "true")
	queryValues.Set("includeImports", "true")
	queryValues.Set("expandSecretReferences", "true")

	requestURL := c.baseURL + "/api/v4/secrets?" + queryValues.Encode()
	var response infisicalSecretsResponse
	if err := c.doAuthenticatedJSON(ctx, http.MethodGet, requestURL, nil, &response); err != nil {
		return nil, err
	}

	secrets := make([]InfisicalSecret, 0, len(response.Secrets))
	for _, secret := range response.Secrets {
		secrets = append(secrets, InfisicalSecret{
			SecretKey:   secret.SecretKey,
			SecretValue: secret.SecretValue,
			SecretPath:  secret.SecretPath,
		})
	}
	return secrets, nil
}

func (c *InfisicalClient) ensureProjectID(ctx context.Context) (string, error) {
	c.mu.Lock()
	projectID := c.projectID
	c.mu.Unlock()
	if projectID != "" {
		return projectID, nil
	}

	requestURL := c.baseURL + "/api/v1/projects/slug/" + url.PathEscape(c.projectSlug)
	var response infisicalProjectResponse
	if err := c.doAuthenticatedJSON(ctx, http.MethodGet, requestURL, nil, &response); err != nil {
		return "", err
	}

	c.mu.Lock()
	c.projectID = response.ID
	c.mu.Unlock()
	return response.ID, nil
}

func (c *InfisicalClient) ensureAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" && time.Now().UTC().Before(c.accessTokenExp) {
		return c.accessToken, nil
	}

	loginBody := infisicalLoginRequest{
		ClientID:     c.machineClientID,
		ClientSecret: c.machineClientSecret,
	}
	var loginResponse infisicalLoginResponse
	if err := c.doJSON(ctx, http.MethodPost, c.baseURL+"/api/v1/auth/universal-auth/login", "", loginBody, &loginResponse); err != nil {
		return "", err
	}
	if loginResponse.AccessToken == "" {
		return "", fmt.Errorf("infisical login returned an empty access token")
	}

	expiry := time.Now().UTC().Add(time.Duration(loginResponse.ExpiresIn) * time.Second)
	if loginResponse.ExpiresIn > 30 {
		expiry = expiry.Add(-30 * time.Second)
	}

	c.accessToken = loginResponse.AccessToken
	c.accessTokenExp = expiry
	return c.accessToken, nil
}

func (c *InfisicalClient) doAuthenticatedJSON(ctx context.Context, method string, requestURL string, requestBody any, responseBody any) error {
	accessToken, err := c.ensureAccessToken(ctx)
	if err != nil {
		return err
	}
	return c.doJSON(ctx, method, requestURL, accessToken, requestBody, responseBody)
}

func (c *InfisicalClient) doJSON(ctx context.Context, method string, requestURL string, bearerToken string, requestBody any, responseBody any) error {
	var bodyReader *strings.Reader
	if requestBody == nil {
		bodyReader = strings.NewReader("")
	} else {
		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = strings.NewReader(string(bodyBytes))
	}

	request, err := http.NewRequestWithContext(ctx, method, requestURL, bodyReader)
	if err != nil {
		return fmt.Errorf("build request %s %s: %w", method, requestURL, err)
	}
	request.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("perform request %s %s: %w", method, requestURL, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("infisical request failed: %w", newHTTPStatusError(method, requestURL, response))
	}
	if responseBody == nil {
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(responseBody); err != nil {
		return fmt.Errorf("decode response %s %s: %w", method, requestURL, err)
	}
	return nil
}
