package main

import (
	"testing"
)

func TestTokenCache(t *testing.T) {
	tc := newTokenCache(300)

	// Empty cache
	if _, ok := tc.get(); ok {
		t.Error("expected empty cache")
	}

	// Set and get
	tc.set("my-token", 300)
	token, ok := tc.get()
	if !ok || token != "my-token" {
		t.Errorf("expected my-token, got %s", token)
	}

	// Invalidate
	tc.invalidate()
	if _, ok := tc.get(); ok {
		t.Error("expected empty cache after invalidate")
	}
}

func TestSignerCache(t *testing.T) {
	sc := newSignerCache(300)

	// Empty cache
	if _, ok := sc.get(); ok {
		t.Error("expected empty cache")
	}

	// Set and get
	signers := []signerResponse{
		{ID: "s1", Name: "signer-1"},
		{ID: "s2", Name: "signer-2"},
	}
	sc.set(signers)

	result, ok := sc.get()
	if !ok {
		t.Fatal("expected cached signers")
	}
	if len(result) != 2 {
		t.Errorf("expected 2 signers, got %d", len(result))
	}
	if result[0].Name != "signer-1" {
		t.Errorf("expected signer-1, got %s", result[0].Name)
	}

	// Invalidate
	sc.invalidate()
	if _, ok := sc.get(); ok {
		t.Error("expected empty cache after invalidate")
	}
}

func TestCertDataCache(t *testing.T) {
	cdc := newCertDataCache(3600)

	// Empty cache
	if _, ok := cdc.getPubKey("s1"); ok {
		t.Error("expected empty pub key cache")
	}
	if _, ok := cdc.getCert("s1"); ok {
		t.Error("expected empty cert cache")
	}

	// Set and get pub key
	pk := pubKeyEntry{PublicKeyDER: []byte{1, 2, 3}, Algorithm: "rsa"}
	cdc.setPubKey("s1", pk)
	result, ok := cdc.getPubKey("s1")
	if !ok {
		t.Fatal("expected cached pub key")
	}
	if result.Algorithm != "rsa" {
		t.Errorf("expected rsa, got %s", result.Algorithm)
	}

	// Set and get cert
	cert := []byte{4, 5, 6}
	cdc.setCert("s1", cert)
	certResult, ok := cdc.getCert("s1")
	if !ok {
		t.Fatal("expected cached cert")
	}
	if len(certResult) != 3 {
		t.Errorf("expected 3 bytes, got %d", len(certResult))
	}
}
