package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestAuthentikClientBuildGrantSnapshot(t *testing.T) {
	t.Parallel()

	tokenCalls := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(t, w, map[string]any{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"jwks_uri":               server.URL + "/keys",
			})
		case "/token":
			tokenCalls++
			writeTestJSON(t, w, map[string]any{
				"access_token": "authentik-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v3/core/users/":
			require.Equal(t, "Bearer authentik-token", r.Header.Get("Authorization"))
			writeTestJSON(t, w, map[string]any{
				"next": "",
				"results": []map[string]any{
					{
						"pk":        1,
						"uid":       "subject-uid-1",
						"username":  "alice",
						"name":      "Alice",
						"email":     "alice@example.com",
						"is_active": true,
						"attributes": map[string]any{
							"sub": "subject-sub-1",
						},
					},
					{
						"pk":         "2",
						"uid":        "subject-sub-2",
						"username":   "bob",
						"name":       "Bob",
						"email":      "bob@example.com",
						"is_active":  true,
						"attributes": map[string]any{},
					},
					{
						"pk":         3,
						"uid":        "subject-sub-3",
						"username":   "carol",
						"name":       "Carol",
						"email":      "carol@example.com",
						"is_active":  false,
						"attributes": map[string]any{},
					},
				},
			})
		case "/api/v3/core/groups/":
			require.Equal(t, "Bearer authentik-token", r.Header.Get("Authorization"))
			writeTestJSON(t, w, map[string]any{
				"next": "",
				"results": []map[string]any{
					{
						"pk":    11,
						"name":  "mcp-service-mealie",
						"users": []any{1},
					},
					{
						"pk":    12,
						"name":  "mcp-admin",
						"users": []any{"2"},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewAuthentikClient(server.URL, "client-id", "client-secret", zerolog.Nop())
	require.NoError(t, err)

	subjects, grants, err := client.BuildGrantSnapshot(context.Background())
	require.NoError(t, err)
	require.Len(t, subjects, 3)
	require.Len(t, grants, 4)

	require.Equal(t, "subject-sub-1", subjects[0].Sub)
	require.Equal(t, "subject-sub-2", subjects[1].Sub)
	require.Equal(t, "subject-sub-3", subjects[2].Sub)

	grantSet := make(map[string]string)
	for _, grant := range grants {
		grantSet[grant.SubjectSub+"::"+grant.ServiceID] = grant.SourceGroup
	}
	require.Equal(t, "mcp-service-mealie", grantSet["subject-sub-1::mealie"])
	require.Equal(t, "mcp-admin", grantSet["subject-sub-2::mealie"])
	require.Equal(t, "mcp-admin", grantSet["subject-sub-2::actualbudget"])
	require.Equal(t, "mcp-admin", grantSet["subject-sub-2::memory"])
	require.Equal(t, 1, tokenCalls)
}

func TestAuthentikClientBuildGrantSnapshotSkipsMalformedRecordsAndUnknownMappings(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(t, w, map[string]any{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"jwks_uri":               server.URL + "/keys",
			})
		case "/token":
			writeTestJSON(t, w, map[string]any{
				"access_token": "authentik-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v3/core/users/":
			writeTestJSON(t, w, map[string]any{
				"next": "",
				"results": []map[string]any{
					{
						"pk":        1,
						"uid":       "subject-sub-1",
						"username":  "alice",
						"name":      "Alice",
						"email":     "alice@example.com",
						"is_active": true,
						"attributes": map[string]any{
							"sub": "subject-sub-1",
						},
					},
					{
						"pk":        []any{"bad"},
						"uid":       "subject-sub-bad",
						"username":  "broken-user",
						"name":      "Broken User",
						"email":     "broken@example.com",
						"is_active": true,
						"attributes": map[string]any{
							"sub": "subject-sub-bad",
						},
					},
					{
						"pk":         3,
						"uid":        "subject-sub-3",
						"username":   "carol",
						"name":       "Carol",
						"email":      "carol@example.com",
						"is_active":  true,
						"attributes": map[string]any{},
					},
				},
			})
		case "/api/v3/core/groups/":
			writeTestJSON(t, w, map[string]any{
				"next": "",
				"results": []map[string]any{
					{
						"pk":    11,
						"name":  "mcp-service-mealie",
						"users": []any{1, map[string]any{"unexpected": "value"}},
					},
					{
						"pk":    []any{"bad"},
						"name":  "mcp-service-memory",
						"users": []any{3},
					},
					{
						"pk":    13,
						"name":  "mcp-service-unknown",
						"users": []any{3},
					},
					{
						"pk":    14,
						"name":  "mcp-admin",
						"users": []any{3},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewAuthentikClient(server.URL, "client-id", "client-secret", zerolog.Nop())
	require.NoError(t, err)

	subjects, grants, err := client.BuildGrantSnapshot(context.Background())
	require.NoError(t, err)
	require.Len(t, subjects, 2)
	require.Len(t, grants, 4)

	subjectSubs := []string{subjects[0].Sub, subjects[1].Sub}
	require.ElementsMatch(t, []string{"subject-sub-1", "subject-sub-3"}, subjectSubs)

	grantSet := make(map[string]string)
	for _, grant := range grants {
		grantSet[grant.SubjectSub+"::"+grant.ServiceID] = grant.SourceGroup
	}

	require.Equal(t, "mcp-service-mealie", grantSet["subject-sub-1::mealie"])
	require.Equal(t, "mcp-admin", grantSet["subject-sub-3::mealie"])
	require.Equal(t, "mcp-admin", grantSet["subject-sub-3::actualbudget"])
	require.Equal(t, "mcp-admin", grantSet["subject-sub-3::memory"])
	_, hasUnknownGrant := grantSet["subject-sub-3::unknown"]
	require.False(t, hasUnknownGrant)
}

func TestAuthentikClientIncludesResponseBodyInHTTPStatusErrors(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(t, w, map[string]any{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/authorize",
				"token_endpoint":         server.URL + "/token",
				"jwks_uri":               server.URL + "/keys",
			})
		case "/token":
			writeTestJSON(t, w, map[string]any{
				"access_token": "authentik-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v3/core/users/":
			http.Error(w, "group sync forbidden", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewAuthentikClient(server.URL, "client-id", "client-secret", zerolog.Nop())
	require.NoError(t, err)

	_, err = client.ListUsers(context.Background())
	require.Error(t, err)
	require.ErrorContains(t, err, "group sync forbidden")
}

func TestJSONRawToString(t *testing.T) {
	t.Parallel()

	value, err := jsonRawToString(json.RawMessage(`123`))
	require.NoError(t, err)
	require.Equal(t, "123", value)

	value, err = jsonRawToString(json.RawMessage(`"abc"`))
	require.NoError(t, err)
	require.Equal(t, "abc", value)
}

func TestRawSliceToStringsSkipsMalformedValues(t *testing.T) {
	t.Parallel()

	values, skipped := rawSliceToStrings([]json.RawMessage{
		json.RawMessage(`1`),
		json.RawMessage(`{"unexpected":"value"}`),
		json.RawMessage(`""`),
		json.RawMessage(`"abc"`),
	})

	require.Equal(t, []string{"1", "abc"}, values)
	require.Equal(t, 2, skipped)
}

func TestNewAuthentikClientPreservesIssuerPrefix(t *testing.T) {
	t.Parallel()

	client, err := NewAuthentikClient("https://auth.example.com/authentik/application/o/mcp-control-plane/", "client-id", "client-secret", zerolog.Nop())
	require.NoError(t, err)
	require.Equal(t, "https://auth.example.com/authentik/api/v3", client.apiBaseURL)
}

func TestAbsolutizeURLRejectsCrossOriginNext(t *testing.T) {
	t.Parallel()

	_, err := absolutizeURL("https://auth.example.com/authentik/api/v3", "https://evil.example.net/next")
	require.Error(t, err)
}
