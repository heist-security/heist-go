package heist

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxErrorBody bounds how much of an error response is read.
const maxErrorBody = 64 << 10

// APIError is a non-2xx response from the Heist API.
type APIError struct {
	// StatusCode is the HTTP status, for example 404.
	StatusCode int
	// Code and Message come from the API's {"error":{"code","message"}} body.
	// They are empty when the body is not that envelope, for example a proxy
	// error page.
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" && e.Message == "" {
		return fmt.Sprintf("heist: HTTP %d %s", e.StatusCode, http.StatusText(e.StatusCode))
	}
	return fmt.Sprintf("heist: HTTP %d: %s: %s", e.StatusCode, e.Code, e.Message)
}

func newAPIError(resp *http.Response) *APIError {
	apiErr := &APIError{StatusCode: resp.StatusCode}
	var envelope Error
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if json.Unmarshal(body, &envelope) == nil {
		apiErr.Code = envelope.Error.Code
		apiErr.Message = envelope.Error.Message
	}
	return apiErr
}

// StatusCode returns the HTTP status of an *APIError, or 0 when err is not
// one (for example, a network or decoding error).
func StatusCode(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// IsNotFound reports whether err is an API 404 response. The API also returns
// 404 for resources hidden from the caller's workspace or role.
func IsNotFound(err error) bool {
	return StatusCode(err) == http.StatusNotFound
}
