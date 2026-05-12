package domain

import (
	"crypto/sha256"
	"encoding/hex"
)

type Subject struct {
	Sub               string
	SubjectKey        string
	PreferredUsername string
	Email             string
	DisplayName       string
}

func DeriveSubjectKey(sub string) string {
	sum := sha256.Sum256([]byte(sub))
	return "u-" + hex.EncodeToString(sum[:])[:16]
}
