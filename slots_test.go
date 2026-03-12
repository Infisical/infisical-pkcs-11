package main

import (
	"testing"
)

func TestObjectHandles(t *testing.T) {
	privHandle := makePrivateKeyHandle(5)
	pubHandle := makePublicKeyHandle(5)
	certHandle := makeCertificateHandle(5)

	objType, slotIdx := parseObjectHandle(privHandle)
	if objType != objPrivateKey {
		t.Errorf("expected objPrivateKey, got 0x%08x", objType)
	}
	if slotIdx != 5 {
		t.Errorf("expected slot index 5, got %d", slotIdx)
	}

	objType, slotIdx = parseObjectHandle(pubHandle)
	if objType != objPublicKey {
		t.Errorf("expected objPublicKey, got 0x%08x", objType)
	}
	if slotIdx != 5 {
		t.Errorf("expected slot index 5, got %d", slotIdx)
	}

	objType, slotIdx = parseObjectHandle(certHandle)
	if objType != objCertificate {
		t.Errorf("expected objCertificate, got 0x%08x", objType)
	}
	if slotIdx != 5 {
		t.Errorf("expected slot index 5, got %d", slotIdx)
	}
}

func TestSessionManager(t *testing.T) {
	sm := newSessionManager()

	// Open sessions
	h1 := sm.open(0)
	h2 := sm.open(0)
	h3 := sm.open(1)

	// Get sessions
	s1, ok := sm.get(h1)
	if !ok || s1.slotID != 0 {
		t.Error("failed to get session 1")
	}

	s3, ok := sm.get(h3)
	if !ok || s3.slotID != 1 {
		t.Error("failed to get session 3")
	}

	// Close session
	if !sm.close(h2) {
		t.Error("failed to close session 2")
	}
	if _, ok := sm.get(h2); ok {
		t.Error("session 2 should be closed")
	}

	// Close all for slot 0
	sm.closeAllForSlot(0)
	if _, ok := sm.get(h1); ok {
		t.Error("session 1 should be closed after closeAllForSlot(0)")
	}
	if _, ok := sm.get(h3); !ok {
		t.Error("session 3 should still be open")
	}

	// Set logged in (per-session)
	sm.setLoggedIn(h3, true)
	s3, ok = sm.get(h3)
	if !ok || !s3.loggedIn {
		t.Error("session 3 should be logged in")
	}

	// Test setAllLoggedInForSlot
	h4 := sm.open(1)
	sm.setAllLoggedInForSlot(1, true)
	s4, ok := sm.get(h4)
	if !ok || !s4.loggedIn {
		t.Error("session 4 should be logged in after setAllLoggedInForSlot")
	}

	// Test appendSignBuffer limits
	s4.signActive = true
	if err := s4.appendSignBuffer(make([]byte, 100)); err != nil {
		t.Errorf("unexpected error on small buffer: %v", err)
	}
	bigBuf := make([]byte, maxSignBuffer+1)
	if err := s4.appendSignBuffer(bigBuf); err == nil {
		t.Error("expected error on buffer exceeding maxSignBuffer")
	}
}
