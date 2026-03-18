package main

import (
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// maxSignBuffer is the maximum accumulated data size for multi-part signing (16 MiB).
// This prevents unbounded memory growth from malicious or buggy callers.
const maxSignBuffer = 16 * 1024 * 1024

const (
	objPrivateKey  uint = 0x10000000
	objCertificate uint = 0x20000000
	objPublicKey   uint = 0x30000000
)

func makePrivateKeyHandle(slotIndex uint) uint {
	return objPrivateKey | slotIndex
}

func makeCertificateHandle(slotIndex uint) uint {
	return objCertificate | slotIndex
}

func makePublicKeyHandle(slotIndex uint) uint {
	return objPublicKey | slotIndex
}

func parseObjectHandle(handle uint) (objType uint, slotIndex uint) {
	return handle & 0xF0000000, handle & 0x0FFFFFFF
}

type session struct {
	slotID          uint
	loggedIn        bool
	signActive      bool
	signMech        uint
	signKeyIndex    uint   // slot index of the key
	signBuffer      []byte // accumulated data from SignUpdate calls
	cachedSignature []byte // cached result after CKR_BUFFER_TOO_SMALL (spec says operation stays active)

	// FindObjects state
	findActive   bool
	findTemplate []*pkcs11.Attribute
	findResults  []uint // object handles matching the template
	findPos      int
}

type sessionManager struct {
	mu       sync.RWMutex
	sessions map[pkcs11.SessionHandle]*session
	nextID   pkcs11.SessionHandle
}

func newSessionManager() *sessionManager {
	return &sessionManager{
		sessions: make(map[pkcs11.SessionHandle]*session),
		nextID:   1,
	}
}

func (m *sessionManager) open(slotID uint) pkcs11.SessionHandle {
	m.mu.Lock()
	defer m.mu.Unlock()
	handle := m.nextID
	m.nextID++
	m.sessions[handle] = &session{slotID: slotID}
	return handle
}

func (m *sessionManager) get(handle pkcs11.SessionHandle) (*session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[handle]
	return s, ok
}

func (m *sessionManager) close(handle pkcs11.SessionHandle) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[handle]; !ok {
		return false
	}
	delete(m.sessions, handle)
	return true
}

func (m *sessionManager) closeAllForSlot(slotID uint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, s := range m.sessions {
		if s.slotID == slotID {
			delete(m.sessions, h)
		}
	}
}

// setLoggedIn sets the login state for a specific session (per PKCS#11 spec).
func (m *sessionManager) setLoggedIn(handle pkcs11.SessionHandle, loggedIn bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[handle]; ok {
		s.loggedIn = loggedIn
	}
}

// setAllLoggedInForSlot sets the login state for all sessions on a slot.
func (m *sessionManager) setAllLoggedInForSlot(slotID uint, loggedIn bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if s.slotID == slotID {
			s.loggedIn = loggedIn
		}
	}
}

func (s *session) appendSignBuffer(data []byte) error {
	newLen := len(s.signBuffer) + len(data)
	if newLen > maxSignBuffer {
		return fmt.Errorf("sign buffer exceeds maximum size (%d bytes)", maxSignBuffer)
	}
	s.signBuffer = append(s.signBuffer, data...)
	return nil
}
