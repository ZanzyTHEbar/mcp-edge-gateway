package edge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"
)

const (
	identityHeaderVersion             = "X-MCP-Identity-Version"
	identityHeaderServiceID           = "X-MCP-Identity-Service-ID"
	identityHeaderSessionID           = "X-MCP-Identity-Session-ID"
	identityHeaderIssuedAt            = "X-MCP-Identity-Issued-At"
	identityHeaderSignature           = "X-MCP-Identity-Signature"
	subjectHeaderSub                  = "X-MCP-Subject-Sub"
	subjectHeaderKey                  = "X-MCP-Subject-Key"
	subjectHeaderEmail                = "X-MCP-Subject-Email"
	subjectHeaderPreferredUsername    = "X-MCP-Subject-Preferred-Username"
	subjectHeaderDisplayName          = "X-MCP-Subject-Display-Name"
	subjectHeaderAccountBindingID     = "X-MCP-Subject-Account-Binding-ID"
	subjectHeaderAccountBindingClaim  = "X-MCP-Subject-Account-Binding-Claim"
	identityHeaderSignatureSchemeV1   = "v1="
	identityContextCanonicalVersionV1 = "v1"
)

type upstreamIdentityHeadersContextKey struct{}

type identityHeaderSigner struct {
	secretPath string
}

type identityHeaderValues struct {
	Version             string
	ServiceID           string
	SessionID           string
	IssuedAt            string
	SubjectSub          string
	SubjectKey          string
	SubjectEmail        string
	SubjectUsername     string
	SubjectDisplayName  string
	AccountBindingID    string
	AccountBindingClaim string
}

func newIdentityHeaderSigner(secretPath string) *identityHeaderSigner {
	return &identityHeaderSigner{secretPath: strings.TrimSpace(secretPath)}
}

func (s *identityHeaderSigner) Headers(service catalog.ServiceCatalogEntry, subject IdentityClaims, sessionID string, now time.Time) (http.Header, error) {
	identityContext := service.IdentityContext.Normalized()
	if identityContext.Mode == catalog.IdentityContextModeNone {
		return nil, nil
	}
	if identityContext.Mode != catalog.IdentityContextModeSignedHeaders {
		return nil, fmt.Errorf("unsupported identity context mode %q", identityContext.Mode)
	}
	if s == nil || strings.TrimSpace(s.secretPath) == "" {
		return nil, fmt.Errorf("identity header secret path is not configured")
	}
	secret, err := resolveConfiguredSecret(s.secretPath, "")
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, fmt.Errorf("identity header secret is empty")
	}

	values := identityHeaderValues{
		Version:             identityContextCanonicalVersionV1,
		ServiceID:           cleanHeaderValue(service.ServiceID),
		SessionID:           cleanHeaderValue(sessionID),
		IssuedAt:            strconv.FormatInt(now.UTC().Unix(), 10),
		SubjectSub:          cleanHeaderValue(subject.Sub),
		SubjectKey:          cleanHeaderValue(firstNonEmpty(subject.SubjectKey, domain.DeriveSubjectKey(subject.Sub))),
		SubjectEmail:        cleanHeaderValue(subject.Email),
		SubjectUsername:     cleanHeaderValue(subject.PreferredUsername),
		SubjectDisplayName:  cleanHeaderValue(subject.Name),
		AccountBindingID:    cleanHeaderValue(subject.AccountBindingID),
		AccountBindingClaim: cleanHeaderValue(subject.AccountBindingClaim),
	}

	signature := signIdentityHeaderValues(secret, values)
	headers := http.Header{}
	headers.Set(identityHeaderVersion, values.Version)
	headers.Set(identityHeaderServiceID, values.ServiceID)
	headers.Set(identityHeaderSessionID, values.SessionID)
	headers.Set(identityHeaderIssuedAt, values.IssuedAt)
	headers.Set(subjectHeaderSub, values.SubjectSub)
	headers.Set(subjectHeaderKey, values.SubjectKey)
	headers.Set(subjectHeaderEmail, values.SubjectEmail)
	headers.Set(subjectHeaderPreferredUsername, values.SubjectUsername)
	headers.Set(subjectHeaderDisplayName, values.SubjectDisplayName)
	headers.Set(subjectHeaderAccountBindingID, values.AccountBindingID)
	headers.Set(subjectHeaderAccountBindingClaim, values.AccountBindingClaim)
	headers.Set(identityHeaderSignature, identityHeaderSignatureSchemeV1+signature)
	return headers, nil
}

func withUpstreamIdentityHeaders(ctx context.Context, headers http.Header) context.Context {
	if len(headers) == 0 {
		return ctx
	}
	return context.WithValue(ctx, upstreamIdentityHeadersContextKey{}, headers.Clone())
}

func applyUpstreamIdentityHeaders(header http.Header, ctx context.Context) {
	stripIdentityContextHeaders(header)
	headers, ok := ctx.Value(upstreamIdentityHeadersContextKey{}).(http.Header)
	if !ok || len(headers) == 0 {
		return
	}
	for key, values := range headers {
		header.Del(key)
		for _, value := range values {
			header.Add(key, value)
		}
	}
}

func stripIdentityContextHeaders(header http.Header) {
	for key := range header {
		lowerKey := strings.ToLower(key)
		if strings.HasPrefix(lowerKey, "x-mcp-identity-") || strings.HasPrefix(lowerKey, "x-mcp-subject-") {
			header.Del(key)
		}
	}
}

func signIdentityHeaderValues(secret string, values identityHeaderValues) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonicalIdentityHeaderPayload(values)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func canonicalIdentityHeaderPayload(values identityHeaderValues) string {
	return strings.Join([]string{
		values.Version,
		values.ServiceID,
		values.SessionID,
		values.IssuedAt,
		values.SubjectSub,
		values.SubjectKey,
		values.SubjectEmail,
		values.SubjectUsername,
		values.SubjectDisplayName,
		values.AccountBindingID,
		values.AccountBindingClaim,
	}, "\n")
}

func cleanHeaderValue(value string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(strings.TrimSpace(value))
}
