package main

import (
	"sync"
	"time"
)

type cacheEntry[T any] struct {
	value     T
	expiresAt time.Time
}

func (e *cacheEntry[T]) isExpired() bool {
	return time.Now().After(e.expiresAt)
}

type signerCache struct {
	mu    sync.RWMutex
	ttl   time.Duration
	entry *cacheEntry[[]signerResponse]
}

func newSignerCache(ttlSeconds int) *signerCache {
	if ttlSeconds == 0 {
		ttlSeconds = 300
	}
	return &signerCache{ttl: time.Duration(ttlSeconds) * time.Second}
}

func (c *signerCache) get() ([]signerResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.entry == nil || c.entry.isExpired() {
		return nil, false
	}
	return c.entry.value, true
}

func (c *signerCache) set(signers []signerResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entry = &cacheEntry[[]signerResponse]{
		value:     signers,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *signerCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entry = nil
}

type pubKeyEntry struct {
	PublicKeyDER []byte // RSA: modulus (big-endian unsigned)
	Exponent     []byte // RSA: public exponent (big-endian unsigned)
	ECParams     []byte // EC: DER-encoded curve OID
	ECPoint      []byte // EC: DER-encoded OCTET STRING of uncompressed point
	Algorithm    string // "RSA" or "EC"
}

type certDataCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	pubKeys map[string]*cacheEntry[pubKeyEntry]
	certs   map[string]*cacheEntry[[]byte]
}

func newCertDataCache(ttlSeconds int) *certDataCache {
	if ttlSeconds == 0 {
		ttlSeconds = 3600
	}
	return &certDataCache{
		ttl:     time.Duration(ttlSeconds) * time.Second,
		pubKeys: make(map[string]*cacheEntry[pubKeyEntry]),
		certs:   make(map[string]*cacheEntry[[]byte]),
	}
}

func (c *certDataCache) getPubKey(signerID string) (*pubKeyEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.pubKeys[signerID]
	if !ok || entry.isExpired() {
		return nil, false
	}
	return &entry.value, true
}

func (c *certDataCache) setPubKey(signerID string, pk pubKeyEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pubKeys[signerID] = &cacheEntry[pubKeyEntry]{
		value:     pk,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *certDataCache) getCert(signerID string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.certs[signerID]
	if !ok || entry.isExpired() {
		return nil, false
	}
	return entry.value, true
}

func (c *certDataCache) setCert(signerID string, cert []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs[signerID] = &cacheEntry[[]byte]{
		value:     cert,
		expiresAt: time.Now().Add(c.ttl),
	}
}
