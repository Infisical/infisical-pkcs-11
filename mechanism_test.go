package main

import (
	"encoding/asn1"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestMechanismToAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		mechanism uint
		expected  string
		wantErr   bool
	}{
		{"SHA256_RSA_PKCS", pkcs11.CKM_SHA256_RSA_PKCS, AlgRSAPKCS1SHA256, false},
		{"SHA384_RSA_PKCS", pkcs11.CKM_SHA384_RSA_PKCS, AlgRSAPKCS1SHA384, false},
		{"SHA512_RSA_PKCS", pkcs11.CKM_SHA512_RSA_PKCS, AlgRSAPKCS1SHA512, false},
		{"SHA256_RSA_PKCS_PSS", pkcs11.CKM_SHA256_RSA_PKCS_PSS, AlgRSAPSSSHA256, false},
		{"ECDSA_SHA256", pkcs11.CKM_ECDSA_SHA256, AlgECDSASHA256, false},
		{"ECDSA_SHA384", pkcs11.CKM_ECDSA_SHA384, AlgECDSASHA384, false},
		{"ECDSA_SHA512", pkcs11.CKM_ECDSA_SHA512, AlgECDSASHA512, false},
		{"ECDSA (raw)", pkcs11.CKM_ECDSA, AlgECDSASHA256, false},
		{"CKM_RSA_PKCS requires DigestInfo", pkcs11.CKM_RSA_PKCS, "", true},
		{"unsupported mechanism", 0xFFFFFFFF, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := mechanismToAlgorithm(tt.mechanism)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if alg != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, alg)
			}
		})
	}
}

// buildDigestInfo creates a DER-encoded DigestInfo structure.
func buildDigestInfo(oid asn1.ObjectIdentifier, digest []byte) []byte {
	algID, _ := asn1.Marshal(algorithmIdentifier{
		Algorithm:  oid,
		Parameters: asn1.RawValue{Tag: 5}, // NULL
	})

	di := digestInfo{
		DigestAlgorithm: asn1.RawValue{FullBytes: algID},
		Digest:          digest,
	}

	data, _ := asn1.Marshal(di)
	return data
}

func TestParseDigestInfo(t *testing.T) {
	sha256Digest := make([]byte, 32) // 256 bits
	sha384Digest := make([]byte, 48)
	sha512Digest := make([]byte, 64)

	tests := []struct {
		name     string
		data     []byte
		expected string
		wantErr  bool
	}{
		{
			"SHA-256 DigestInfo",
			buildDigestInfo(oidSHA256, sha256Digest),
			AlgRSAPKCS1SHA256,
			false,
		},
		{
			"SHA-384 DigestInfo",
			buildDigestInfo(oidSHA384, sha384Digest),
			AlgRSAPKCS1SHA384,
			false,
		},
		{
			"SHA-512 DigestInfo",
			buildDigestInfo(oidSHA512, sha512Digest),
			AlgRSAPKCS1SHA512,
			false,
		},
		{
			"invalid data",
			[]byte{0x01, 0x02, 0x03},
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, _, err := parseDigestInfo(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if alg != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, alg)
			}
		})
	}
}
