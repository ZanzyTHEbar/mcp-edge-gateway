package ids

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"dragonserver/mcp-platform/internal/platform/faults"
)

// UUID represents a 16-byte RFC-9562 UUIDv7 value.
type UUID [16]byte

func Parse(s string) (UUID, error) {
	var out UUID
	b, err := ToBytes(s)
	if err != nil {
		return out, err
	}
	copy(out[:], b[:])
	if err := out.Validate(); err != nil {
		return UUID{}, err
	}
	return out, nil
}

func ParseRequired(s string) (UUID, error) { return Parse(s) }

func MustParse(s string) UUID {
	u, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func (u UUID) Bytes() []byte { return u[:][:] }

func (u UUID) IsZero() bool {
	for _, b := range u {
		if b != 0 {
			return false
		}
	}
	return true
}

func (u UUID) IsV7() bool { return u[6]&0xf0 == 0x70 && u[8]&0xc0 == 0x80 }

func (u UUID) Validate() error {
	if u.IsZero() {
		return faults.New(faults.CodeValidationFailed, "uuid is required", "field", "uuid")
	}
	if u[6]&0xf0 != 0x70 {
		return faults.New(faults.CodeValidationFailed, "invalid uuid version", "field", "uuid", "version", int(u[6]>>4))
	}
	if u[8]&0xc0 != 0x80 {
		return faults.New(faults.CodeValidationFailed, "invalid uuid variant", "field", "uuid")
	}
	return nil
}

func (u UUID) String() string { return encodeCanonical([16]byte(u)) }

func (u UUID) Value() (driver.Value, error) { return []byte(u[:]), nil }

func (u *UUID) Scan(src interface{}) error {
	if src == nil {
		return nil
	}
	switch v := src.(type) {
	case []byte:
		if len(v) == 36 {
			parsed, err := Parse(string(v))
			if err != nil {
				return err
			}
			*u = parsed
			return nil
		}
		if len(v) != 16 {
			return faults.New(faults.CodeValidationFailed, fmt.Sprintf("invalid uuid blob length: %d", len(v)), "field", "uuid", "length", len(v))
		}
		parsed, err := ParseBytes(v)
		if err != nil {
			return err
		}
		*u = parsed
		return nil
	case string:
		parsed, err := Parse(v)
		if err != nil {
			return err
		}
		*u = parsed
		return nil
	default:
		return faults.New(faults.CodeValidationFailed, "unsupported uuid scan source type", "type", fmt.Sprintf("%T", src))
	}
}

func (u UUID) MarshalJSON() ([]byte, error) { return json.Marshal(u.String()) }

func (u *UUID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return faults.Wrap(faults.CodeValidationFailed, "decode uuid json", err, "field", "uuid")
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}
