package server

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

type apiError struct {
	status  int
	Code    string        `json:"error" example:"validation_error" doc:"Stable machine-readable error code"`
	Message string        `json:"message" example:"Validation failed." doc:"Human-readable error message"`
	Details []errorDetail `json:"details,omitempty" doc:"Optional validation error details"`
}

type errorDetail struct {
	Location string `json:"location,omitempty"`
	Message  string `json:"message"`
}

func (e *apiError) Error() string  { return e.Message }
func (e *apiError) GetStatus() int { return e.status }

func init() {
	huma.NewError = newAPIError
	huma.NewErrorWithContext = func(_ huma.Context, status int, message string, errs ...error) huma.StatusError {
		return newAPIError(status, message, errs...)
	}
}

func newAPIError(status int, message string, errs ...error) huma.StatusError {
	details := make([]errorDetail, 0, len(errs))
	for _, err := range errs {
		if detailer, ok := err.(huma.ErrorDetailer); ok {
			detail := detailer.ErrorDetail()
			details = append(details, errorDetail{Location: detail.Location, Message: detail.Message})
			continue
		}
		details = append(details, errorDetail{Message: err.Error()})
	}
	return &apiError{
		status:  status,
		Code:    errorCode(status, message),
		Message: message,
		Details: details,
	}
}

func errorCode(status int, message string) string {
	switch message {
	case "invalid credentials":
		return "invalid_credentials"
	case "invalid token":
		return "invalid_token"
	case "invalid refresh token":
		return "invalid_token"
	case "email already exists":
		return "email_already_exists"
	case "invalid registration":
		return "validation_error"
	case "database unavailable", "authentication service unavailable":
		return "service_unavailable"
	}

	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return "validation_error"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	default:
		if status >= http.StatusInternalServerError {
			return "internal_error"
		}
	}

	code := strings.ToLower(strings.TrimSpace(message))
	code = strings.NewReplacer(" ", "_", "-", "_").Replace(code)
	if code == "" {
		return "request_error"
	}
	return code
}
