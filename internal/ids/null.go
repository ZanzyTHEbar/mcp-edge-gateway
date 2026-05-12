package ids

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"dragonserver/mcp-platform/internal/platform/faults"
)

type NullUUID struct {
	UUID  UUID
	Valid bool
}

func FromPtr(u *UUID) NullUUID {
	if u == nil {
		return NullUUID{}
	}
	return NullUUID{UUID: *u, Valid: true}
}

func (n NullUUID) Ptr() *UUID {
	if !n.Valid {
		return nil
	}
	u := n.UUID
	return &u
}

func (n *NullUUID) Scan(src interface{}) error {
	if src == nil {
		*n = NullUUID{}
		return nil
	}
	var u UUID
	if err := u.Scan(src); err != nil {
		return err
	}
	n.UUID = u
	n.Valid = true
	return nil
}

func (n NullUUID) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return n.UUID.Value()
}

func (n NullUUID) MarshalJSON() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	return n.UUID.MarshalJSON()
}

func (n *NullUUID) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*n = NullUUID{}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return faults.Wrap(faults.CodeValidationFailed, "decode nullable uuid", err, "type", fmt.Sprintf("%T", s))
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	n.UUID = parsed
	n.Valid = true
	return nil
}
