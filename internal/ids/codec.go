package ids

import (
	"encoding/hex"

	"dragonserver/mcp-platform/internal/platform/faults"
)

func ToBytes(u string) ([16]byte, error) {
	var out [16]byte
	if len(u) != 36 {
		return out, faults.New(faults.CodeValidationFailed, "invalid uuid length", "field", "uuid", "length", len(u))
	}
	if u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
		return out, faults.New(faults.CodeValidationFailed, "invalid uuid format", "field", "uuid")
	}
	var s [32]byte
	j := 0
	for i := 0; i < len(u); i++ {
		if u[i] == '-' {
			continue
		}
		if !isCanonicalHex(u[i]) {
			return out, faults.New(faults.CodeValidationFailed, "invalid uuid format", "field", "uuid")
		}
		s[j] = u[i]
		j++
	}
	b, err := hex.DecodeString(string(s[:]))
	if err != nil {
		return out, faults.Wrap(faults.CodeValidationFailed, "decode uuid", err, "field", "uuid")
	}
	copy(out[:], b)
	if err := UUID(out).Validate(); err != nil {
		return [16]byte{}, err
	}
	return out, nil
}

func isCanonicalHex(b byte) bool { return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') }

func ParseBytes(b []byte) (UUID, error) {
	var out UUID
	if len(b) != 16 {
		return out, faults.New(faults.CodeValidationFailed, "invalid uuid blob length", "field", "uuid", "length", len(b))
	}
	copy(out[:], b)
	if err := out.Validate(); err != nil {
		return UUID{}, err
	}
	return out, nil
}

func MustToBytes(u string) []byte {
	b, err := ToBytes(u)
	if err != nil {
		panic(err)
	}
	return b[:]
}

func FromBytes(b []byte) UUID {
	out, err := ParseBytes(b)
	if err != nil {
		panic(err)
	}
	return out
}

func FromString(s string) UUID { return MustParse(s) }
