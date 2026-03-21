package catalog

type TransportType string

const (
	TransportTypeStreamableHTTP TransportType = "streamable-http"
	TransportTypeSSE            TransportType = "sse"
)

type AdapterRequirement string

const (
	AdapterRequirementNone                   AdapterRequirement = "none"
	AdapterRequirementPathTranslation        AdapterRequirement = "path-translation"
	AdapterRequirementSSEToHTTPNormalization AdapterRequirement = "sse-to-http-normalization"
)

type SecretDefinition struct {
	Key      string
	Required bool
}

type ServiceCatalogEntry struct {
	ServiceID              string
	DisplayName            string
	UpstreamServiceName    string
	TransportType          TransportType
	InternalPort           int
	PublicPath             string
	InternalUpstreamPath   string
	HealthPath             string
	HealthProbeExpectation string
	ResourceProfile        string
	PersistencePolicy      string
	AdapterRequirement     AdapterRequirement
	SecretContract         []SecretDefinition
}

func DefaultCatalogV1() []ServiceCatalogEntry {
	return []ServiceCatalogEntry{
		{
			ServiceID:              "mealie",
			DisplayName:            "Mealie",
			UpstreamServiceName:    "mealie-mcp",
			TransportType:          TransportTypeStreamableHTTP,
			InternalPort:           3031,
			PublicPath:             "/mealie/mcp",
			InternalUpstreamPath:   "/mcp",
			HealthPath:             "/mcp",
			HealthProbeExpectation: "GET returns discovery JSON with transport=streamable-http",
			ResourceProfile:        "small",
			PersistencePolicy:      "stateless",
			AdapterRequirement:     AdapterRequirementNone,
			SecretContract: []SecretDefinition{
				{Key: "api-token", Required: true},
			},
		},
		{
			ServiceID:              "actualbudget",
			DisplayName:            "Actual Budget",
			UpstreamServiceName:    "actualbudget-mcp",
			TransportType:          TransportTypeStreamableHTTP,
			InternalPort:           3000,
			PublicPath:             "/actualbudget/mcp",
			InternalUpstreamPath:   "/http",
			HealthPath:             "/http",
			HealthProbeExpectation: "GET reaches a live MCP endpoint and returns a JSON-RPC no-session error rather than connection failure",
			ResourceProfile:        "small",
			PersistencePolicy:      "stateless",
			AdapterRequirement:     AdapterRequirementPathTranslation,
			SecretContract: []SecretDefinition{
				{Key: "actual-api-key", Required: true},
				{Key: "budget-sync-id", Required: true},
				{Key: "actual-budget-encryption-password", Required: false},
			},
		},
		{
			ServiceID:              "memory",
			DisplayName:            "Memory",
			UpstreamServiceName:    "memory",
			TransportType:          TransportTypeSSE,
			InternalPort:           8090,
			PublicPath:             "/memory/mcp",
			InternalUpstreamPath:   "/sse",
			HealthPath:             "/sse",
			HealthProbeExpectation: "GET returns text/event-stream and emits an endpoint event",
			ResourceProfile:        "medium",
			PersistencePolicy:      "stateful-libsql",
			AdapterRequirement:     AdapterRequirementSSEToHTTPNormalization,
			SecretContract: []SecretDefinition{
				{Key: "libsql-url", Required: true},
				{Key: "libsql-auth-token", Required: true},
			},
		},
	}
}
