package faults

import errbuilder "github.com/ZanzyTHEbar/errbuilder-go"

type Code string

const (
	CodeUnknown Code = "unknown"

	CodeConfigRequired Code = "config.required"
	CodeConfigInvalid  Code = "config.invalid"

	CodeDependencyMissing   Code = "dependency.missing"
	CodeValidationFailed    Code = "validation.failed"
	CodeInvariantFailed     Code = "invariant.failed"
	CodeUnreachable         Code = "unreachable"
	CodeNotFound            Code = "not_found"
	CodeAuthorizationDenied Code = "authorization.denied"
	CodeResourceLimit       Code = "resource.limit"

	CodeDatabaseOpen      Code = "database.open"
	CodeDatabaseRead      Code = "database.read"
	CodeDatabaseWrite     Code = "database.write"
	CodeDatabaseClose     Code = "database.close"
	CodeDatabaseMigration Code = "database.migration"
)

func (c Code) String() string {
	if c == "" {
		return string(CodeUnknown)
	}
	return string(c)
}

func (c Code) ErrCode() errbuilder.ErrCode {
	switch c {
	case CodeConfigRequired, CodeConfigInvalid, CodeValidationFailed:
		return errbuilder.CodeInvalidArgument
	case CodeNotFound:
		return errbuilder.CodeNotFound
	case CodeAuthorizationDenied:
		return errbuilder.CodePermissionDenied
	case CodeResourceLimit:
		return errbuilder.CodeResourceExhausted
	case CodeDependencyMissing:
		return errbuilder.CodeFailedPrecondition
	case CodeDatabaseOpen:
		return errbuilder.CodeUnavailable
	case CodeInvariantFailed, CodeUnreachable, CodeDatabaseRead, CodeDatabaseWrite, CodeDatabaseClose, CodeDatabaseMigration:
		return errbuilder.CodeInternal
	default:
		return errbuilder.CodeUnknown
	}
}
