package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type AuthentikClient struct {
	logger       zerolog.Logger
	issuerURL    string
	clientID     string
	clientSecret string
	apiBaseURL   string
	httpClient   *http.Client

	mu          sync.Mutex
	tokenSource oauth2.TokenSource
}

type AuthentikUser struct {
	PK         string
	UID        string
	Username   string
	Name       string
	Email      string
	IsActive   bool
	Attributes map[string]any
}

type AuthentikGroup struct {
	PK         string
	Name       string
	UserIDs    []string
	Attributes map[string]any
}

type authentikListResponse struct {
	Next    string            `json:"next"`
	Results []json.RawMessage `json:"results"`
}

type authentikUserResponse struct {
	PK         json.RawMessage `json:"pk"`
	UID        string          `json:"uid"`
	Username   string          `json:"username"`
	Name       string          `json:"name"`
	Email      string          `json:"email"`
	IsActive   bool            `json:"is_active"`
	Attributes map[string]any  `json:"attributes"`
}

type authentikGroupResponse struct {
	PK         json.RawMessage   `json:"pk"`
	Name       string            `json:"name"`
	Users      []json.RawMessage `json:"users"`
	Attributes map[string]any    `json:"attributes"`
}

func NewAuthentikClient(issuerURL string, clientID string, clientSecret string, logger zerolog.Logger) (*AuthentikClient, error) {
	if strings.TrimSpace(issuerURL) == "" {
		return nil, fmt.Errorf("authentik issuer url is required")
	}
	if strings.TrimSpace(clientID) == "" {
		return nil, fmt.Errorf("authentik client id is required")
	}
	if strings.TrimSpace(clientSecret) == "" {
		return nil, fmt.Errorf("authentik client secret is required")
	}

	parsedIssuer, err := url.Parse(strings.TrimSpace(issuerURL))
	if err != nil {
		return nil, fmt.Errorf("parse authentik issuer url: %w", err)
	}
	apiPrefixPath := strings.TrimSuffix(parsedIssuer.Path, "/")
	if prefixIndex := strings.Index(apiPrefixPath, "/application/o/"); prefixIndex >= 0 {
		apiPrefixPath = apiPrefixPath[:prefixIndex]
	}
	apiBaseURL := parsedIssuer.Scheme + "://" + parsedIssuer.Host + apiPrefixPath + "/api/v3"

	return &AuthentikClient{
		logger:       logger,
		issuerURL:    strings.TrimSpace(issuerURL),
		clientID:     strings.TrimSpace(clientID),
		clientSecret: strings.TrimSpace(clientSecret),
		apiBaseURL:   apiBaseURL,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}, nil
}

func NewAuthentikClientFromConfig(ctx context.Context, cfg Config, secrets SecretResolver, logger zerolog.Logger) (*AuthentikClient, error) {
	if secrets == nil {
		return nil, fmt.Errorf("secret resolver is required")
	}
	clientSecret, err := secrets.ResolveSecretReference(ctx, cfg.AuthentikClientSecretPath)
	if err != nil {
		return nil, err
	}
	return NewAuthentikClient(cfg.AuthentikIssuerURL, cfg.AuthentikClientID, clientSecret, logger)
}

func (c *AuthentikClient) ListUsers(ctx context.Context) ([]AuthentikUser, error) {
	var users []AuthentikUser
	requestURL := c.apiBaseURL + "/core/users/"
	var err error
	for requestURL != "" {
		var page authentikListResponse
		if err := c.doJSON(ctx, requestURL, &page); err != nil {
			return nil, err
		}
		for resultIndex, item := range page.Results {
			user, err := decodeAuthentikUser(item)
			if err != nil {
				c.logger.Warn().
					Err(err).
					Int("result_index", resultIndex).
					Str("request_url", requestURL).
					Msg("skipping malformed authentik user")
				continue
			}
			users = append(users, user)
		}
		requestURL, err = absolutizeURL(c.apiBaseURL, page.Next)
		if err != nil {
			return nil, err
		}
	}

	return users, nil
}

func (c *AuthentikClient) ListGroups(ctx context.Context) ([]AuthentikGroup, error) {
	var groups []AuthentikGroup
	requestURL := c.apiBaseURL + "/core/groups/"
	var err error
	for requestURL != "" {
		var page authentikListResponse
		if err := c.doJSON(ctx, requestURL, &page); err != nil {
			return nil, err
		}
		for resultIndex, item := range page.Results {
			group, skippedUserIDs, err := decodeAuthentikGroup(item)
			if err != nil {
				c.logger.Warn().
					Err(err).
					Int("result_index", resultIndex).
					Str("request_url", requestURL).
					Msg("skipping malformed authentik group")
				continue
			}
			if skippedUserIDs > 0 {
				c.logger.Warn().
					Str("group_name", group.Name).
					Str("group_pk", group.PK).
					Int("skipped_user_refs", skippedUserIDs).
					Msg("skipping malformed authentik group membership references")
			}
			groups = append(groups, group)
		}
		requestURL, err = absolutizeURL(c.apiBaseURL, page.Next)
		if err != nil {
			return nil, err
		}
	}

	return groups, nil
}

func (c *AuthentikClient) BuildGrantSnapshot(ctx context.Context) ([]domain.Subject, []ServiceGrant, error) {
	users, err := c.ListUsers(ctx)
	if err != nil {
		return nil, nil, err
	}
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return nil, nil, err
	}

	groupMemberships := make(map[string][]string)
	for _, group := range groups {
		for _, userID := range group.UserIDs {
			groupMemberships[userID] = append(groupMemberships[userID], group.Name)
		}
	}

	supportedServices := make([]string, 0, len(catalog.DefaultCatalogV1()))
	for _, entry := range catalog.DefaultCatalogV1() {
		supportedServices = append(supportedServices, entry.ServiceID)
	}

	now := time.Now().UTC()
	subjectsBySub := make(map[string]domain.Subject, len(users))
	subjectOrder := make([]string, 0, len(users))
	grants := make([]ServiceGrant, 0)
	seenGrantKeys := make(map[string]struct{})

	for _, user := range users {
		subjectSub := SubjectSubFromAuthentikUser(user)
		if subjectSub == "" {
			c.logger.Warn().
				Str("user_pk", user.PK).
				Str("username", user.Username).
				Msg("skipping authentik user without usable subject identifier")
			continue
		}
		if _, exists := subjectsBySub[subjectSub]; exists {
			c.logger.Warn().
				Str("subject_sub", subjectSub).
				Str("user_pk", user.PK).
				Str("username", user.Username).
				Msg("skipping duplicate authentik subject identifier")
			continue
		}

		subjectsBySub[subjectSub] = domain.Subject{
			Sub:               subjectSub,
			SubjectKey:        domain.DeriveSubjectKey(subjectSub),
			PreferredUsername: user.Username,
			Email:             user.Email,
			DisplayName:       user.Name,
		}
		subjectOrder = append(subjectOrder, subjectSub)
		if !user.IsActive {
			continue
		}

		serviceGrants, ignoredGroups := deriveServiceGrants(groupMemberships[user.PK], supportedServices)
		if len(ignoredGroups) > 0 {
			c.logger.Warn().
				Str("subject_sub", subjectSub).
				Strs("ignored_groups", ignoredGroups).
				Msg("ignoring unsupported authentik service-group mappings")
		}
		for serviceID, sourceGroup := range serviceGrants {
			grantKey := subjectSub + "\x00" + serviceID
			if _, exists := seenGrantKeys[grantKey]; exists {
				continue
			}
			seenGrantKeys[grantKey] = struct{}{}
			grants = append(grants, ServiceGrant{
				SubjectSub:   subjectSub,
				ServiceID:    serviceID,
				SourceGroup:  sourceGroup,
				GrantedAt:    now,
				LastSyncedAt: now,
			})
		}
	}

	subjects := make([]domain.Subject, 0, len(subjectOrder))
	for _, subjectSub := range subjectOrder {
		subjects = append(subjects, subjectsBySub[subjectSub])
	}

	return subjects, grants, nil
}

func (c *AuthentikClient) SyncStore(ctx context.Context, store *Store) error {
	if store == nil {
		return fmt.Errorf("store is required")
	}

	subjects, grants, err := c.BuildGrantSnapshot(ctx)
	if err != nil {
		return err
	}

	return store.SyncSubjectGrantSnapshot(ctx, subjects, grants)
}

func SubjectSubFromAuthentikUser(user AuthentikUser) string {
	if rawSubject, ok := user.Attributes["sub"].(string); ok && strings.TrimSpace(rawSubject) != "" {
		return strings.TrimSpace(rawSubject)
	}
	if strings.TrimSpace(user.UID) != "" {
		return strings.TrimSpace(user.UID)
	}
	if strings.TrimSpace(user.PK) != "" {
		return "authentik|" + strings.TrimSpace(user.PK)
	}
	return ""
}

func deriveServiceGrants(groupNames []string, supportedServices []string) (map[string]string, []string) {
	grants := make(map[string]string)
	supportedServiceSet := make(map[string]struct{}, len(supportedServices))
	for _, serviceID := range supportedServices {
		supportedServiceSet[serviceID] = struct{}{}
	}
	ignoredGroups := make([]string, 0)
	for _, groupName := range groupNames {
		groupName = strings.TrimSpace(groupName)
		if groupName == "" {
			continue
		}

		if groupName == "mcp-admin" {
			for _, serviceID := range supportedServices {
				if _, exists := grants[serviceID]; !exists {
					grants[serviceID] = groupName
				}
			}
			continue
		}

		if !strings.HasPrefix(groupName, "mcp-service-") {
			continue
		}
		serviceID := strings.TrimPrefix(groupName, "mcp-service-")
		if serviceID == "" {
			continue
		}
		if _, ok := supportedServiceSet[serviceID]; !ok {
			ignoredGroups = append(ignoredGroups, groupName)
			continue
		}
		grants[serviceID] = groupName
	}
	return grants, ignoredGroups
}

func (c *AuthentikClient) ensureTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tokenSource != nil {
		return c.tokenSource, nil
	}

	provider, err := oidc.NewProvider(ctx, c.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover authentik oidc provider: %w", err)
	}
	endpoint := provider.Endpoint()
	if strings.TrimSpace(endpoint.TokenURL) == "" {
		return nil, fmt.Errorf("authentik oidc provider does not expose a token endpoint")
	}

	oauthConfig := clientcredentials.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		TokenURL:     endpoint.TokenURL,
	}
	c.tokenSource = oauthConfig.TokenSource(ctx)
	return c.tokenSource, nil
}

func (c *AuthentikClient) doJSON(ctx context.Context, requestURL string, responseBody any) error {
	tokenSource, err := c.ensureTokenSource(ctx)
	if err != nil {
		return err
	}

	token, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("fetch authentik access token: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("build authentik request %s: %w", requestURL, err)
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("perform authentik request %s: %w", requestURL, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("authentik request failed: %w", newHTTPStatusError(http.MethodGet, requestURL, response))
	}
	if err := json.NewDecoder(response.Body).Decode(responseBody); err != nil {
		return fmt.Errorf("decode authentik response %s: %w", requestURL, err)
	}
	return nil
}

func jsonRawToString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}

	var stringValue string
	if err := json.Unmarshal(raw, &stringValue); err == nil {
		return strings.TrimSpace(stringValue), nil
	}

	var intValue int64
	if err := json.Unmarshal(raw, &intValue); err == nil {
		return strconv.FormatInt(intValue, 10), nil
	}

	var objectValue map[string]json.RawMessage
	if err := json.Unmarshal(raw, &objectValue); err == nil {
		for _, candidateKey := range []string{"pk", "id", "uid", "uuid"} {
			candidateValue, ok := objectValue[candidateKey]
			if !ok {
				continue
			}
			return jsonRawToString(candidateValue)
		}
	}

	return "", fmt.Errorf("unsupported raw value %s", string(raw))
}

func rawSliceToStrings(rawValues []json.RawMessage) ([]string, int) {
	values := make([]string, 0, len(rawValues))
	skipped := 0
	for _, rawValue := range rawValues {
		value, err := jsonRawToString(rawValue)
		if err != nil {
			skipped++
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			skipped++
			continue
		}
		values = append(values, value)
	}
	return values, skipped
}

func decodeAuthentikUser(raw json.RawMessage) (AuthentikUser, error) {
	var item authentikUserResponse
	if err := json.Unmarshal(raw, &item); err != nil {
		return AuthentikUser{}, fmt.Errorf("decode authentik user: %w", err)
	}

	pk, err := jsonRawToString(item.PK)
	if err != nil {
		return AuthentikUser{}, fmt.Errorf("parse authentik user pk: %w", err)
	}
	pk = strings.TrimSpace(pk)
	if pk == "" {
		return AuthentikUser{}, fmt.Errorf("authentik user pk is empty")
	}

	return AuthentikUser{
		PK:         pk,
		UID:        strings.TrimSpace(item.UID),
		Username:   strings.TrimSpace(item.Username),
		Name:       strings.TrimSpace(item.Name),
		Email:      strings.TrimSpace(item.Email),
		IsActive:   item.IsActive,
		Attributes: item.Attributes,
	}, nil
}

func decodeAuthentikGroup(raw json.RawMessage) (AuthentikGroup, int, error) {
	var item authentikGroupResponse
	if err := json.Unmarshal(raw, &item); err != nil {
		return AuthentikGroup{}, 0, fmt.Errorf("decode authentik group: %w", err)
	}

	pk, err := jsonRawToString(item.PK)
	if err != nil {
		return AuthentikGroup{}, 0, fmt.Errorf("parse authentik group pk: %w", err)
	}
	pk = strings.TrimSpace(pk)
	if pk == "" {
		return AuthentikGroup{}, 0, fmt.Errorf("authentik group pk is empty")
	}

	userIDs, skippedUserIDs := rawSliceToStrings(item.Users)
	return AuthentikGroup{
		PK:         pk,
		Name:       strings.TrimSpace(item.Name),
		UserIDs:    userIDs,
		Attributes: item.Attributes,
	}, skippedUserIDs, nil
}

func absolutizeURL(baseURL string, nextURL string) (string, error) {
	trimmedNext := strings.TrimSpace(nextURL)
	if trimmedNext == "" {
		return "", nil
	}
	parsedNext, err := url.Parse(trimmedNext)
	if err != nil {
		return "", fmt.Errorf("parse next page url %q: %w", nextURL, err)
	}
	if parsedNext.IsAbs() {
		if !sameOrigin(parsedBaseURL(baseURL), parsedNext) {
			return "", fmt.Errorf("refusing cross-origin pagination url %q", nextURL)
		}
		return parsedNext.String(), nil
	}

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base url %q: %w", baseURL, err)
	}
	resolvedURL := parsedBase.ResolveReference(parsedNext)
	if !sameOrigin(parsedBase, resolvedURL) {
		return "", fmt.Errorf("refusing cross-origin pagination url %q", resolvedURL.String())
	}
	return resolvedURL.String(), nil
}

func parsedBaseURL(rawURL string) *url.URL {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return &url.URL{}
	}
	return parsedURL
}

func sameOrigin(left *url.URL, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}
