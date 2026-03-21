package controlplane

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitInfisicalSecretReference(t *testing.T) {
	t.Parallel()

	secretPath, secretKey, err := SplitInfisicalSecretReference("/subjects/u-123/services/mealie/api-token")
	require.NoError(t, err)
	require.Equal(t, "/subjects/u-123/services/mealie", secretPath)
	require.Equal(t, "api-token", secretKey)
}

func TestReadSecretFromFile(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	secretPath := filepath.Join(tempDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretPath, []byte("  top-secret  \n"), 0o600))

	secretValue, err := ReadSecretFromFile(secretPath)
	require.NoError(t, err)
	require.Equal(t, "top-secret", secretValue)
}
