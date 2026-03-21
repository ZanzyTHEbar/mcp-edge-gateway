package edge

import "context"

type AuthenticatedSubject struct {
	Sub               string
	Email             string
	DisplayName       string
	PreferredUsername string
	Groups            []string
}

type subjectContextKey struct{}

func WithAuthenticatedSubject(ctx context.Context, subject AuthenticatedSubject) context.Context {
	return context.WithValue(ctx, subjectContextKey{}, subject)
}

func SubjectFromContext(ctx context.Context) (AuthenticatedSubject, bool) {
	subject, ok := ctx.Value(subjectContextKey{}).(AuthenticatedSubject)
	return subject, ok
}
