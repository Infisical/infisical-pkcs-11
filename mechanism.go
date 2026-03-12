package main

import (
	"encoding/asn1"
	"fmt"

	"github.com/miekg/pkcs11"
)

const (
	AlgRSAPKCS1SHA256 = "RSASSA_PKCS1_V1_5_SHA_256"
	AlgRSAPKCS1SHA384 = "RSASSA_PKCS1_V1_5_SHA_384"
	AlgRSAPKCS1SHA512 = "RSASSA_PKCS1_V1_5_SHA_512"
	AlgRSAPSSSHA256   = "RSASSA_PSS_SHA_256"
	AlgRSAPSSSHA384   = "RSASSA_PSS_SHA_384"
	AlgRSAPSSSHA512   = "RSASSA_PSS_SHA_512"
	AlgECDSASHA256    = "ECDSA_SHA_256"
	AlgECDSASHA384    = "ECDSA_SHA_384"
	AlgECDSASHA512    = "ECDSA_SHA_512"
)

const (
	sha256DigestLen = 32
	sha384DigestLen = 48
	sha512DigestLen = 64
)

// mechanismToAlgorithm maps a PKCS#11 mechanism to an Infisical signing algorithm.
func mechanismToAlgorithm(mechanism uint) (string, error) {
	switch mechanism {
	case pkcs11.CKM_SHA256_RSA_PKCS:
		return AlgRSAPKCS1SHA256, nil
	case pkcs11.CKM_SHA384_RSA_PKCS:
		return AlgRSAPKCS1SHA384, nil
	case pkcs11.CKM_SHA512_RSA_PKCS:
		return AlgRSAPKCS1SHA512, nil
	case pkcs11.CKM_SHA256_RSA_PKCS_PSS:
		return AlgRSAPSSSHA256, nil
	case pkcs11.CKM_SHA384_RSA_PKCS_PSS:
		return AlgRSAPSSSHA384, nil
	case pkcs11.CKM_SHA512_RSA_PKCS_PSS:
		return AlgRSAPSSSHA512, nil
	case pkcs11.CKM_ECDSA_SHA256:
		return AlgECDSASHA256, nil
	case pkcs11.CKM_ECDSA_SHA384:
		return AlgECDSASHA384, nil
	case pkcs11.CKM_ECDSA_SHA512:
		return AlgECDSASHA512, nil
	case pkcs11.CKM_ECDSA:
		return AlgECDSASHA256, nil
	case pkcs11.CKM_RSA_PKCS:
		return "", fmt.Errorf("CKM_RSA_PKCS requires DigestInfo parsing")
	default:
		return "", fmt.Errorf("unsupported mechanism: 0x%08x", mechanism)
	}
}

// DigestInfo is the DER-encoded structure per PKCS#1 v1.5:
//
//	DigestInfo ::= SEQUENCE {
//	  digestAlgorithm AlgorithmIdentifier,
//	  digest          OCTET STRING
//	}
type digestInfo struct {
	DigestAlgorithm asn1.RawValue
	Digest          []byte
}

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// parseDigestInfo extracts the signing algorithm from a DER-encoded DigestInfo
// structure (used with CKM_RSA_PKCS raw signing).
func parseDigestInfo(data []byte) (algorithm string, digest []byte, err error) {
	var di digestInfo
	rest, err := asn1.Unmarshal(data, &di)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse DigestInfo: %w", err)
	}
	if len(rest) > 0 {
		return "", nil, fmt.Errorf("trailing data after DigestInfo (%d bytes)", len(rest))
	}

	var algID algorithmIdentifier
	if _, err := asn1.Unmarshal(di.DigestAlgorithm.FullBytes, &algID); err != nil {
		return "", nil, fmt.Errorf("failed to parse AlgorithmIdentifier: %w", err)
	}

	switch {
	case algID.Algorithm.Equal(oidSHA256):
		if len(di.Digest) != sha256DigestLen {
			return "", nil, fmt.Errorf("SHA-256 DigestInfo has wrong digest length: got %d, want %d", len(di.Digest), sha256DigestLen)
		}
		return AlgRSAPKCS1SHA256, di.Digest, nil
	case algID.Algorithm.Equal(oidSHA384):
		if len(di.Digest) != sha384DigestLen {
			return "", nil, fmt.Errorf("SHA-384 DigestInfo has wrong digest length: got %d, want %d", len(di.Digest), sha384DigestLen)
		}
		return AlgRSAPKCS1SHA384, di.Digest, nil
	case algID.Algorithm.Equal(oidSHA512):
		if len(di.Digest) != sha512DigestLen {
			return "", nil, fmt.Errorf("SHA-512 DigestInfo has wrong digest length: got %d, want %d", len(di.Digest), sha512DigestLen)
		}
		return AlgRSAPKCS1SHA512, di.Digest, nil
	default:
		return "", nil, fmt.Errorf("unsupported hash OID in DigestInfo: %v", algID.Algorithm)
	}
}

var rsaMechanisms = []uint{
	pkcs11.CKM_RSA_PKCS,
	pkcs11.CKM_SHA256_RSA_PKCS,
	pkcs11.CKM_SHA384_RSA_PKCS,
	pkcs11.CKM_SHA512_RSA_PKCS,
	pkcs11.CKM_SHA256_RSA_PKCS_PSS,
	pkcs11.CKM_SHA384_RSA_PKCS_PSS,
	pkcs11.CKM_SHA512_RSA_PKCS_PSS,
}

var ecMechanisms = []uint{
	pkcs11.CKM_ECDSA,
	pkcs11.CKM_ECDSA_SHA256,
	pkcs11.CKM_ECDSA_SHA384,
	pkcs11.CKM_ECDSA_SHA512,
}
