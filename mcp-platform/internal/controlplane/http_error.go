package controlplane

import (
	"errors"
	"io"
	"net/http"
	"strings"
)

type HTTPStatusError struct {
	Method     string
	URL        string
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	message := e.Method + " " + e.URL + " failed with status " + itoa(e.StatusCode)
	if e.Body != "" {
		message += ": " + e.Body
	}
	return message
}

func IsHTTPStatus(err error, statusCode int) bool {
	var target *HTTPStatusError
	if !errors.As(err, &target) {
		return false
	}
	return target.StatusCode == statusCode
}

func newHTTPStatusError(method string, requestURL string, response *http.Response) *HTTPStatusError {
	return &HTTPStatusError{
		Method:     method,
		URL:        requestURL,
		StatusCode: response.StatusCode,
		Body:       readHTTPErrorBody(response.Body),
	}
}

func readHTTPErrorBody(body io.Reader) string {
	if body == nil {
		return ""
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(body, 2048))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(bodyBytes))
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}

	sign := ""
	if value < 0 {
		sign = "-"
		value = -value
	}

	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}

	return sign + string(digits[index:])
}
