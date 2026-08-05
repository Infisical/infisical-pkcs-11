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
		{"401 with mechanism message stays USER_NOT_LOGGED_IN", &APIError{StatusCode: 401, Message: "Mechanism not supported"}, pkcs11.CKR_USER_NOT_LOGGED_IN},
		{"403 with mechanism message stays GENERAL_ERROR", &APIError{StatusCode: 403, Message: "algorithm not supported for this context"}, pkcs11.CKR_GENERAL_ERROR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapAPIError(tt.apiErr); got != tt.expected {
				t.Errorf("expected 0x%08x, got 0x%08x", tt.expected, got)
			}
		})
	}
}

func TestIsApprovalRequired(t *testing.T) {
	cases := []struct {
		name string
		err  *APIError
		want bool
	}{
		// Bodies captured from a live instance: the sign route sets error to the thrown error's
		// name, which is why the code is authoritative here.
		{"403 approval required", &APIError{StatusCode: 403, Code: "ApprovalRequired"}, true},
		{"403 generic forbidden name", &APIError{StatusCode: 403, Code: "ForbiddenError"}, false},
		{"403 permission denied", &APIError{StatusCode: 403, Code: "PermissionDenied"}, false},
		{"403 token error", &APIError{StatusCode: 403, Code: "TokenError"}, false},
		{"403 with no code (proxy or WAF, not Infisical)", &APIError{StatusCode: 403, Code: ""}, false},
		{"401", &APIError{StatusCode: 401, Code: "ApprovalRequired"}, false},
		{"404", &APIError{StatusCode: 404, Code: ""}, false},
		{"500", &APIError{StatusCode: 500, Code: ""}, false},
	}
	for _, c := range cases {
		if got := c.err.IsApprovalRequired(); got != c.want {
			t.Errorf("%s: IsApprovalRequired() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRedactionCoversPropertyStyleCredentials(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"gradle property", []string{"gradle", "-Psigning.password=s3cret"}, "gradle -Psigning.password=***"},
		{"gradle camel case", []string{"gradle", "-PsigningPassword=s3cret"}, "gradle -PsigningPassword=***"},
		{"java system property", []string{"java", "-Dsigning.keyPassword=s3cret"}, "java -Dsigning.keyPassword=***"},
		{"bare assignment", []string{"make", "PASSWORD=s3cret"}, "make PASSWORD=***"},
		{"msbuild sub-key", []string{"msbuild", "/p:Password=s3cret"}, "msbuild /p:Password=***"},
		{"separate value", []string{"jarsigner", "-storepass", "hunter2"}, "jarsigner -storepass ***"},
		// A secret flag given no value must not consume the following flag's value.
		{"missing value", []string{"jarsigner", "-storepass", "-keypass", "hunter3"}, "jarsigner -storepass -keypass ***"},
		{"passwd suffix", []string{"tool", "--db-passwd=s3cret"}, "tool --db-passwd=***"},
		{"colon value", []string{"tool", "-pass:s3cret"}, "tool -pass:***"},
		// A sub-key without an inline value must not swallow the next argument.
		{"sub-key without value", []string{"signtool", "/p:pass", "app.exe"}, "signtool /p:*** app.exe"},
	}
	for _, c := range cases {
		if got := joinCommandArgs(redactCommandArgs(c.args)); got != c.want {
			t.Errorf("%s:\n  got  %s\n  want %s", c.name, got, c.want)
		}
	}
}
