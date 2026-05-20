package edge

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/catalog"

	"github.com/stretchr/testify/require"
)

func TestIdentityHeaderSignerBuildsSignedHeaders(t *testing.T) {
	t.Parallel()

	secretPath := filepath.Join(t.TempDir(), "identity-secret")
	require.NoError(t, os.WriteFile(secretPath, []byte("shared-secret\n"), 0o600))
	signer := newIdentityHeaderSigner(secretPath)
	service := catalog.ServiceCatalogEntry{
		ServiceID: "penpot",
		IdentityContext: catalog.IdentityContextConfig{
			Mode: catalog.IdentityContextModeSignedHeaders,
		},
	}
	subject := IdentityClaims{
		Sub:                 "authentik-sub",
		SubjectKey:          "subject-key",
		Email:               "user@example.com",
		Name:                "Example User",
		PreferredUsername:   "example",
		AccountBindingID:    "stable-user-id",
		AccountBindingClaim: "dragonserver_user_id",
	}
	now := time.Unix(1234567890, 0).UTC()

	headers, err := signer.Headers(service, subject, "session-id", now)
	require.NoError(t, err)

	values := identityHeaderValues{
		Version:             identityContextCanonicalVersionV1,
		ServiceID:           "penpot",
		SessionID:           "session-id",
		IssuedAt:            "1234567890",
		SubjectSub:          "authentik-sub",
		SubjectKey:          "subject-key",
		SubjectEmail:        "user@example.com",
		SubjectUsername:     "example",
		SubjectDisplayName:  "Example User",
		AccountBindingID:    "stable-user-id",
		AccountBindingClaim: "dragonserver_user_id",
	}
	require.Equal(t, "v1="+signIdentityHeaderValues("shared-secret", values), headers.Get(identityHeaderSignature))
	require.Equal(t, "stable-user-id", headers.Get(subjectHeaderAccountBindingID))
	require.Equal(t, "dragonserver_user_id", headers.Get(subjectHeaderAccountBindingClaim))
}

func TestIdentityHeaderSignerRequiresSecretForOptInService(t *testing.T) {
	t.Parallel()

	signer := newIdentityHeaderSigner("")
	service := catalog.ServiceCatalogEntry{
		ServiceID: "penpot",
		IdentityContext: catalog.IdentityContextConfig{
			Mode: catalog.IdentityContextModeSignedHeaders,
		},
	}

	_, err := signer.Headers(service, IdentityClaims{Sub: "subject"}, "session-id", time.Now())
	require.ErrorContains(t, err, "identity header secret path is not configured")
}
