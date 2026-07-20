package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// Sentinel errors for PKCS#11 return value mapping.
var (
	ErrNotLoggedIn          = errors.New("not logged in")
	ErrSessionHandleInvalid = errors.New("invalid session handle")
	ErrSlotIDInvalid        = errors.New("slot index out of range")
	ErrSignNotActive        = errors.New("sign operation not initialized")
	ErrSignAlreadyActive    = errors.New("sign operation already active")
	ErrFindAlreadyActive    = errors.New("find already active")
	ErrFindNotActive        = errors.New("find not active")
)

// APIError represents an error response from the Infisical API.
type APIError struct {
	StatusCode int
	Message    string
	Operation  string
}

func (e *APIError) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("%s: API error %d: %s", e.Operation, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

func NewAPIError(operation string, statusCode int, message string) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    message,
		Operation:  operation,
	}
}

type RequestError struct {
	Operation string
	Err       error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("%s: %v", e.Operation, e.Err)
}

func (e *RequestError) Unwrap() error {
	return e.Err
}

func isUnsupportedMechanismMessage(msg string) bool {
	m := strings.ToLower(msg)
	if strings.Contains(m, "mechanism_invalid") {
		return true
	}
	if !strings.Contains(m, "mechanism") && !strings.Contains(m, "algorithm") {
		return false
	}
	return strings.Contains(m, "not supported") || strings.Contains(m, "does not support") || strings.Contains(m, "unsupported")
}

func mapAPIError(apiErr *APIError) uint {
	if apiErr.StatusCode == 400 && isUnsupportedMechanismMessage(apiErr.Message) {
		return pkcs11.CKR_MECHANISM_INVALID
	}
	return mapHTTPError(apiErr.StatusCode)
}

func mapHTTPError(statusCode int) uint {
	switch {
	case statusCode == 401:
		return pkcs11.CKR_USER_NOT_LOGGED_IN
	case statusCode == 403:
		// 403 = permission denied or approval required
		return pkcs11.CKR_GENERAL_ERROR
	case statusCode == 404:
		return pkcs11.CKR_KEY_HANDLE_INVALID
	case statusCode == 400:
		return pkcs11.CKR_DATA_INVALID
	case statusCode >= 500:
		return pkcs11.CKR_DEVICE_ERROR
	default:
		return pkcs11.CKR_GENERAL_ERROR
	}
}
