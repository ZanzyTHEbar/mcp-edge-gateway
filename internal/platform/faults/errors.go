package faults

import (
	"context"
	"errors"
)

import errbuilder "github.com/ZanzyTHEbar/errbuilder-go"

func New(code Code, msg string, fields ...any) error {
	return errbuilder.New().
		WithCode(code.ErrCode()).
		WithLabel(code.String()).
		WithMsg(msg).
		WithCause(errors.New(msg)).
		WithDetails(newDetails(fields...))
}

func Wrap(code Code, msg string, cause error, fields ...any) error {
	if cause == nil {
		return nil
	}
	return errbuilder.New().
		WithCode(errCodeForCause(code, cause)).
		WithLabel(code.String()).
		WithMsg(msg).
		WithCause(cause).
		WithDetails(newDetails(fields...))
}

func errCodeForCause(code Code, cause error) errbuilder.ErrCode {
	if errors.Is(cause, context.Canceled) {
		return errbuilder.CodeCanceled
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return errbuilder.CodeDeadlineExceeded
	}
	return code.ErrCode()
}
