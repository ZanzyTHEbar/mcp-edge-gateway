package selfcheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveHTTPURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		bindAddr        string
		defaultBindAddr string
		path            string
		expectedURL     string
	}{
		{
			name:            "use explicit wildcard port",
			bindAddr:        ":8081",
			defaultBindAddr: ":9999",
			path:            "/health/ready",
			expectedURL:     "http://127.0.0.1:8081/health/ready",
		},
		{
			name:            "use ipv4 wildcard host",
			bindAddr:        "0.0.0.0:8080",
			defaultBindAddr: ":9999",
			path:            "health/ready",
			expectedURL:     "http://127.0.0.1:8080/health/ready",
		},
		{
			name:            "use ipv6 wildcard host",
			bindAddr:        "[::]:9090",
			defaultBindAddr: ":9999",
			path:            "/health/live",
			expectedURL:     "http://127.0.0.1:9090/health/live",
		},
		{
			name:            "preserve explicit loopback host",
			bindAddr:        "127.0.0.1:8081",
			defaultBindAddr: ":9999",
			path:            "/health",
			expectedURL:     "http://127.0.0.1:8081/health",
		},
		{
			name:            "use default bind addr when unset",
			bindAddr:        "",
			defaultBindAddr: ":8081",
			path:            "/health/ready",
			expectedURL:     "http://127.0.0.1:8081/health/ready",
		},
		{
			name:            "accept bare port",
			bindAddr:        "7070",
			defaultBindAddr: ":8081",
			path:            "/health/ready",
			expectedURL:     "http://127.0.0.1:7070/health/ready",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actualURL, err := ResolveHTTPURL(testCase.bindAddr, testCase.defaultBindAddr, testCase.path)

			require.NoError(t, err)
			require.Equal(t, testCase.expectedURL, actualURL)
		})
	}
}

func TestResolveHTTPURLError(t *testing.T) {
	t.Parallel()

	_, err := ResolveHTTPURL("localhost", ":8081", "/health/ready")

	require.Error(t, err)
	require.Contains(t, err.Error(), "missing port")
}
