package controlplane

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
)

type SecretResolver interface {
	ResolveSecretReference(context.Context, string) (string, error)
}

func IsInfisicalSecretReference(reference string) bool {
	return strings.HasPrefix(reference, "/platform/") || strings.HasPrefix(reference, "/subjects/")
}

func ReadSecretFromFile(filePath string) (string, error) {
	trimmedPath := strings.TrimSpace(filePath)
	if trimmedPath == "" {
		return "", fmt.Errorf("secret file path is required")
	}

	content, err := os.ReadFile(trimmedPath)
	if err != nil {
		return "", fmt.Errorf("read secret file %q: %w", trimmedPath, err)
	}
	secretValue := strings.TrimSpace(string(content))
	if secretValue == "" {
		return "", fmt.Errorf("secret file %q is empty", trimmedPath)
	}
	return secretValue, nil
}

func SplitInfisicalSecretReference(reference string) (string, string, error) {
	cleanReference := path.Clean(strings.TrimSpace(reference))
	if cleanReference == "" || cleanReference == "." || cleanReference == "/" {
		return "", "", fmt.Errorf("invalid infisical secret reference %q", reference)
	}
	if !strings.HasPrefix(cleanReference, "/") {
		return "", "", fmt.Errorf("infisical secret reference must be absolute: %q", reference)
	}

	secretPath, secretKey := path.Split(cleanReference)
	secretPath = strings.TrimSuffix(secretPath, "/")
	secretKey = strings.TrimSpace(secretKey)
	if secretPath == "" || secretKey == "" {
		return "", "", fmt.Errorf("invalid infisical secret reference %q", reference)
	}

	return secretPath, secretKey, nil
}

func localFileExists(filePath string) bool {
	trimmedPath := strings.TrimSpace(filePath)
	if trimmedPath == "" {
		return false
	}

	fileInfo, err := os.Stat(trimmedPath)
	if err != nil {
		return false
	}
	return !fileInfo.IsDir()
}
