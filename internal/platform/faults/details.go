package faults

import (
	"errors"
	"fmt"
)

import errbuilder "github.com/ZanzyTHEbar/errbuilder-go"

type assertStringData string

func (d assertStringData) Dump() string { return string(d) }

func newDetails(fields ...any) errbuilder.ErrDetails {
	var errs errbuilder.ErrorMap
	for _, pair := range normalizeFields(fields...) {
		if pair.value == nil {
			errs.Set(pair.key, "<nil>")
			continue
		}
		if err, ok := pair.value.(error); ok {
			errs.Set(pair.key, err)
			continue
		}
		errs.Set(pair.key, fmt.Sprint(pair.value))
	}
	return errbuilder.NewErrDetails(errs)
}

type fieldPair struct {
	key   string
	value any
}

func normalizeFields(fields ...any) []fieldPair {
	pairs := make([]fieldPair, 0, (len(fields)+1)/2)
	if len(fields)%2 != 0 {
		pairs = append(pairs, fieldPair{key: "fault_field_error", value: "odd field count"})
	}
	for i := 0; i < len(fields); i += 2 {
		key := fmt.Sprintf("field_%d", i/2)
		if fields[i] != nil {
			key = fmt.Sprint(fields[i])
		}
		if key == "" {
			key = fmt.Sprintf("field_%d", i/2)
		}
		var value any = "<missing>"
		if i+1 < len(fields) {
			value = fields[i+1]
		}
		pairs = append(pairs, fieldPair{key: key, value: value})
	}
	return pairs
}

func recoveredError(recovered any) error {
	switch value := recovered.(type) {
	case nil:
		return nil
	case error:
		return value
	case string:
		return errors.New(value)
	default:
		return fmt.Errorf("panic: %v", value)
	}
}
