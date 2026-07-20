package main

import (
	"testing"

	"github.com/miekg/pkcs11"
)

func TestMapHTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   uint
	}{
		{"401 -> USER_NOT_LOGGED_IN", 401, pkcs11.CKR_USER_NOT_LOGGED_IN},
		{"403 -> GENERAL_ERROR", 403, pkcs11.CKR_GENERAL_ERROR},
		{"404 -> KEY_HANDLE_INVALID", 404, pkcs11.CKR_KEY_HANDLE_INVALID},
		{"400 -> DATA_INVALID", 400, pkcs11.CKR_DATA_INVALID},
		{"500 -> DEVICE_ERROR", 500, pkcs11.CKR_DEVICE_ERROR},
		{"502 -> DEVICE_ERROR", 502, pkcs11.CKR_DEVICE_ERROR},
		{"418 -> GENERAL_ERROR", 418, pkcs11.CKR_GENERAL_ERROR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapHTTPError(tt.statusCode)
			if result != tt.expected {
				t.Errorf("expected 0x%08x, got 0x%08x", tt.expected, result)
			}
		})
	}
}

func TestIsUnsupportedMechanismMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{"gateway structured code", "PKCS#11 request failed (mechanism_invalid): The HSM does not support the requested signing algorithm", true},
		{"gateway HSM phrase", "Mechanism not supported by this HSM", true},
		{"api pre-check phrase", "Signing algorithm RSASSA_PKCS1_V1_5_SHA_256 is not supported on HSM-backed certificates", true},
		{"unsupported wording", "unsupported mechanism", true},
		{"key/algorithm mismatch is NOT a mechanism issue", "RSA key cannot be used with signing algorithm ECDSA_SHA_256", false},
		{"generic bad request", "Data exceeds maximum size of 128 bytes", false},
		{"key not found", "Private key with label \"x\" not found", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUnsupportedMechanismMessage(tt.msg); got != tt.want {
				t.Errorf("isUnsupportedMechanismMessage(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}

func TestMapAPIError(t *testing.T) {
	tests := []struct {
		name     string
		apiErr   *APIError
		expected uint
	}{
		{"mechanism invalid -> MECHANISM_INVALID", &APIError{StatusCode: 400, Message: "PKCS#11 request failed (mechanism_invalid): ..."}, pkcs11.CKR_MECHANISM_INVALID},
		{"plain 400 -> DATA_INVALID", &APIError{StatusCode: 400, Message: "Data exceeds maximum size"}, pkcs11.CKR_DATA_INVALID},
		{"401 -> USER_NOT_LOGGED_IN", &APIError{StatusCode: 401, Message: "unauthorized"}, pkcs11.CKR_USER_NOT_LOGGED_IN},
		{"500 -> DEVICE_ERROR", &APIError{StatusCode: 500, Message: "internal"}, pkcs11.CKR_DEVICE_ERROR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapAPIError(tt.apiErr); got != tt.expected {
				t.Errorf("expected 0x%08x, got 0x%08x", tt.expected, got)
			}
		})
	}
}
