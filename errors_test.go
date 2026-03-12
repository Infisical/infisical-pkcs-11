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
