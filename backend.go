package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/rs/zerolog"
)

var version = "dev"

var ErrAlreadyInitialized = errors.New("already initialized")

// CKC_X_509 is the PKCS#11 certificate type for X.509 certificates.
const CKC_X_509 = 0

type InfisicalBackend struct {
	mu sync.RWMutex

	initialized bool
	config      *Config
	client      *InfisicalClient
	sessions    *sessionManager
	log         zerolog.Logger

	signerCache *signerCache
	certCache   *certDataCache
}

var backend = &InfisicalBackend{}

func (b *InfisicalBackend) Initialize() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.initialized {
		return ErrAlreadyInitialized
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	b.config = cfg

	b.log = b.initLogger(cfg)

	client, err := newInfisicalClient(cfg)
	if err != nil {
		return err
	}
	b.client = client
	b.sessions = newSessionManager()
	b.signerCache = newSignerCache(cfg.Cache.SignerTTLSeconds)
	b.certCache = newCertDataCache(cfg.Cache.CertTTLSeconds)
	b.initialized = true

	// Pre-authenticate so slot listing works without C_Login
	if cfg.Auth.ClientID != "" && cfg.Auth.ClientSecret != "" {
		if err := b.authenticate(cfg.Auth.ClientID, cfg.Auth.ClientSecret); err != nil {
			b.log.Warn().Err(err).Msg("Auto-login failed during init (user can still login via C_Login)")
		} else {
			b.log.Info().Msg("Initialized with universal-auth (auto-authenticated)")
		}
	} else if cfg.Auth.Method == authMethodToken && cfg.Auth.Token != "" {
		b.log.Info().Msg("Initialized with token auth")
	}

	b.log.Info().Str("version", version).Msg("PKCS#11 module initialized")
	return nil
}

func (b *InfisicalBackend) initLogger(cfg *Config) zerolog.Logger {
	var writer io.Writer = os.Stderr

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			writer = f
		}
	}

	consoleWriter := zerolog.ConsoleWriter{
		Out:        writer,
		TimeFormat: time.RFC3339,
		NoColor:    cfg.LogFile != "", // no color when writing to file
	}

	level := zerolog.InfoLevel
	switch strings.ToLower(cfg.LogLevel) {
	case "trace":
		level = zerolog.TraceLevel
	case "debug":
		level = zerolog.DebugLevel
	case "warn":
		level = zerolog.WarnLevel
	case "error":
		level = zerolog.ErrorLevel
	}

	return zerolog.New(consoleWriter).
		Level(level).
		With().
		Timestamp().
		Str("component", "infisical-pkcs11").
		Logger()
}

func (b *InfisicalBackend) Finalize() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.initialized {
		return nil
	}
	b.initialized = false
	b.log.Info().Msg("Finalized")
	return nil
}

func (b *InfisicalBackend) authenticate(clientID, clientSecret string) error {
	return b.client.UniversalAuthLogin(clientID, clientSecret)
}

func (b *InfisicalBackend) getToken() (string, error) {
	if b.config.Auth.Method == authMethodToken {
		if b.config.Auth.Token == "" {
			return "", fmt.Errorf("token auth: no token provided; pass it as the C_Login PIN or set %s", envToken)
		}
		return b.config.Auth.Token, nil
	}
	token := b.client.GetAccessToken()
	if token != "" {
		return token, nil
	}
	// Token empty — try re-authenticating if config credentials are available.
	if b.config.Auth.ClientID != "" && b.config.Auth.ClientSecret != "" {
		if err := b.authenticate(b.config.Auth.ClientID, b.config.Auth.ClientSecret); err != nil {
			return "", err
		}
		token = b.client.GetAccessToken()
		if token != "" {
			return token, nil
		}
		return "", fmt.Errorf("token not available after re-auth")
	}
	return "", fmt.Errorf("no access token and no credentials available for re-auth")
}

// withRetryOnAuth executes fn, and if it returns a 401 APIError, re-authenticates
// via the SDK and retries once.
func (b *InfisicalBackend) withRetryOnAuth(fn func(token string) error) error {
	token, err := b.getToken()
	if err != nil {
		return err
	}
	err = fn(token)
	if err == nil {
		return nil
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 401 {
		return err
	}

	// Token auth uses a static token with nothing to re-authenticate; surface the 401 instead of
	// silently falling back to any universal-auth credentials left in the environment.
	if b.config.Auth.Method == authMethodToken {
		return err
	}

	// 401 — re-authenticate and retry once.
	b.log.Debug().Msg("Received 401, re-authenticating and retrying")

	if b.config.Auth.ClientID != "" && b.config.Auth.ClientSecret != "" {
		if authErr := b.authenticate(b.config.Auth.ClientID, b.config.Auth.ClientSecret); authErr != nil {
			return authErr
		}
	}

	newToken := b.client.GetAccessToken()
	if newToken == "" || newToken == token {
		// Token unchanged or empty
		return err
	}
	return fn(newToken)
}

func (b *InfisicalBackend) getSigners() ([]signerResponse, error) {
	if signers, ok := b.signerCache.get(); ok {
		return signers, nil
	}

	var signers []signerResponse
	err := b.withRetryOnAuth(func(token string) error {
		var callErr error
		signers, callErr = b.client.ListSigners(token)
		return callErr
	})
	if err != nil {
		return nil, err
	}

	b.signerCache.set(signers)
	return signers, nil
}

func (b *InfisicalBackend) getSignerBySlot(slotIndex uint) (*signerResponse, error) {
	signers, err := b.getSigners()
	if err != nil {
		return nil, err
	}
	if slotIndex >= uint(len(signers)) {
		return nil, fmt.Errorf("%w: slot %d (have %d signers)", ErrSlotIDInvalid, slotIndex, len(signers))
	}
	return &signers[slotIndex], nil
}

func (b *InfisicalBackend) GetSlotList(tokenPresent bool) ([]uint, error) {
	signers, err := b.getSigners()
	if err != nil {
		return nil, err
	}
	slots := make([]uint, len(signers))
	for i := range signers {
		slots[i] = uint(i)
	}
	return slots, nil
}

func (b *InfisicalBackend) GetSlotInfo(slotID uint) (pkcs11.SlotInfo, error) {
	signer, err := b.getSignerBySlot(slotID)
	if err != nil {
		return pkcs11.SlotInfo{}, err
	}

	return pkcs11.SlotInfo{
		SlotDescription: padString(signer.Name, 64),
		ManufacturerID:  padString("Infisical", 32),
		Flags:           pkcs11.CKF_TOKEN_PRESENT | pkcs11.CKF_HW_SLOT,
		HardwareVersion: pkcs11.Version{Major: 1, Minor: 0},
		FirmwareVersion: pkcs11.Version{Major: 1, Minor: 0},
	}, nil
}

func (b *InfisicalBackend) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	signer, err := b.getSignerBySlot(slotID)
	if err != nil {
		return pkcs11.TokenInfo{}, err
	}

	// The module auto-authenticates when it has universal-auth credentials or a token
	flags := pkcs11.CKF_TOKEN_INITIALIZED
	if !b.hasConfigCredentials() && !b.isTokenAuth() {
		flags |= pkcs11.CKF_LOGIN_REQUIRED
	}

	return pkcs11.TokenInfo{
		Label:           padString(signer.Name, 32),
		ManufacturerID:  padString("Infisical", 32),
		Model:           padString("Code Signing", 16),
		SerialNumber:    padString(truncate(signer.ID, 16), 16),
		Flags:           uint(flags),
		MaxSessionCount: 64,
		SessionCount:    0,
		MaxPinLen:       4096,
		MinPinLen:       1,
		HardwareVersion: pkcs11.Version{Major: 1, Minor: 0},
		FirmwareVersion: pkcs11.Version{Major: 1, Minor: 0},
	}, nil
}

func (b *InfisicalBackend) hasConfigCredentials() bool {
	return b.config.Auth.ClientID != "" && b.config.Auth.ClientSecret != ""
}

func (b *InfisicalBackend) isTokenAuth() bool {
	return b.config.Auth.Method == authMethodToken && b.config.Auth.Token != ""
}

func (b *InfisicalBackend) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	if _, err := b.getSignerBySlot(slotID); err != nil {
		return 0, err
	}
	handle := b.sessions.open(slotID)

	if b.isTokenAuth() || (b.hasConfigCredentials() && b.client.GetAccessToken() != "") {
		b.sessions.setLoggedIn(handle, true)
	}

	b.log.Debug().Uint("slot", slotID).Uint("session", uint(handle)).Msg("Opened session")
	return handle, nil
}

func (b *InfisicalBackend) CloseSession(sh pkcs11.SessionHandle) error {
	if !b.sessions.close(sh) {
		return ErrSessionHandleInvalid
	}
	return nil
}

func (b *InfisicalBackend) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return ErrSessionHandleInvalid
	}

	if pin != "" {
		if clientID, clientSecret, isCreds := splitClientCreds(pin); isCreds {
			if err := b.authenticate(clientID, clientSecret); err != nil {
				b.log.Warn().Err(err).Msg("Login failed")
				return err
			}
			b.sessions.setLoggedIn(sh, true)
			b.sessions.setAllLoggedInForSlot(sess.slotID, true)
			b.log.Debug().Uint("slot", sess.slotID).Msg("Login successful (universal-auth via PIN)")
			return nil
		}
		b.config.Auth.Method = authMethodToken
		b.config.Auth.Token = pin
		b.sessions.setLoggedIn(sh, true)
		b.sessions.setAllLoggedInForSlot(sess.slotID, true)
		b.log.Debug().Uint("slot", sess.slotID).Msg("Login successful (token via PIN)")
		return nil
	}

	// No PIN: fall back to the configured credentials.
	if b.config.Auth.Method == authMethodToken {
		if b.config.Auth.Token == "" {
			return fmt.Errorf("token auth: no token provided; pass it as the PIN or set %s", envToken)
		}
		b.sessions.setLoggedIn(sh, true)
		b.sessions.setAllLoggedInForSlot(sess.slotID, true)
		b.log.Debug().Uint("slot", sess.slotID).Msg("Login successful (token auth)")
		return nil
	}

	// Universal auth: reuse a cached token from auto-auth, otherwise log in with config credentials.
	if b.client.GetAccessToken() != "" && b.hasConfigCredentials() {
		b.sessions.setLoggedIn(sh, true)
		b.sessions.setAllLoggedInForSlot(sess.slotID, true)
		b.log.Debug().Uint("slot", sess.slotID).Msg("Login successful (cached token)")
		return nil
	}
	if b.config.Auth.ClientID == "" {
		return fmt.Errorf("no credentials: provide a PIN (clientId:clientSecret or an access token), or configure them")
	}
	if err := b.authenticate(b.config.Auth.ClientID, b.config.Auth.ClientSecret); err != nil {
		b.log.Warn().Err(err).Msg("Login failed")
		return err
	}
	b.sessions.setLoggedIn(sh, true)
	b.sessions.setAllLoggedInForSlot(sess.slotID, true)
	b.log.Info().Uint("slot", sess.slotID).Msg("Login successful")
	return nil
}

func splitClientCreds(pin string) (clientID, clientSecret string, ok bool) {
	parts := strings.SplitN(pin, ":", 2)
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], true
	}
	return "", "", false
}

func (b *InfisicalBackend) Logout(sh pkcs11.SessionHandle) error {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return ErrSessionHandleInvalid
	}
	b.sessions.setAllLoggedInForSlot(sess.slotID, false)
	return nil
}

func (b *InfisicalBackend) GetMechanismList(slotID uint) ([]*pkcs11.Mechanism, error) {
	signer, err := b.getSignerBySlot(slotID)
	if err != nil {
		return nil, err
	}

	var mechs []uint
	keyAlg := signer.keyAlgorithm()

	switch {
	case strings.Contains(keyAlg, "rsa"):
		mechs = rsaMechanisms
	case strings.Contains(keyAlg, "ec"):
		mechs = ecMechanisms
	default:
		mechs = append(rsaMechanisms, ecMechanisms...)
	}

	result := make([]*pkcs11.Mechanism, len(mechs))
	for i, m := range mechs {
		result[i] = pkcs11.NewMechanism(m, nil)
	}
	return result, nil
}

func setEmptyFindResult(sess *session, template []*pkcs11.Attribute) {
	sess.findActive = true
	sess.findTemplate = template
	sess.findResults = nil
	sess.findPos = 0
}

func (b *InfisicalBackend) FindObjectsInit(sh pkcs11.SessionHandle, template []*pkcs11.Attribute) error {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return ErrSessionHandleInvalid
	}
	if sess.findActive {
		return ErrFindAlreadyActive
	}

	var results []uint
	requestedClass := uint(0)
	hasClassFilter := false
	var requestedID []byte
	var requestedLabel []byte
	var requestedSubject []byte

	for _, attr := range template {
		switch attr.Type {
		case pkcs11.CKA_CLASS:
			if len(attr.Value) >= 4 {
				requestedClass = uint(attr.Value[0]) | uint(attr.Value[1])<<8 | uint(attr.Value[2])<<16 | uint(attr.Value[3])<<24
				hasClassFilter = true
			}
		case pkcs11.CKA_ID:
			requestedID = attr.Value
		case pkcs11.CKA_LABEL:
			requestedLabel = attr.Value
		case pkcs11.CKA_SUBJECT:
			requestedSubject = attr.Value
		}
	}

	slotIdx := sess.slotID

	// If filtering by CKA_ID or CKA_LABEL, verify the signer matches
	if requestedID != nil || requestedLabel != nil {
		signer, err := b.getSignerBySlot(slotIdx)
		if err != nil {
			return err
		}
		if requestedID != nil {
			signerID := truncate(signer.ID, 20)
			if string(requestedID) != signerID {
				setEmptyFindResult(sess, template)
				return nil
			}
		}
		if requestedLabel != nil {
			if string(requestedLabel) != signer.Name {
				setEmptyFindResult(sess, template)
				return nil
			}
		}
	}

	// Filter by CKA_SUBJECT: compare DER-encoded subject against the certificate's actual subject.
	// Many tools (Java, OpenSSL, NSS) use this to search for issuer certs during chain building.
	if requestedSubject != nil {
		signer, err := b.getSignerBySlot(slotIdx)
		if err != nil {
			return err
		}
		certData, err := b.getCertificateData(signer.ID)
		if err != nil {
			setEmptyFindResult(sess, template)
			return nil
		}
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			setEmptyFindResult(sess, template)
			return nil
		}
		if !bytes.Equal(requestedSubject, cert.RawSubject) {
			b.log.Debug().
				Str("signer", signer.Name).
				Msg("CKA_SUBJECT filter: no match (cert chain issuer not found locally)")
			setEmptyFindResult(sess, template)
			return nil
		}
	}

	if hasClassFilter {
		switch requestedClass {
		case pkcs11.CKO_PRIVATE_KEY:
			results = []uint{makePrivateKeyHandle(slotIdx)}
		case pkcs11.CKO_CERTIFICATE:
			results = []uint{makeCertificateHandle(slotIdx)}
		case pkcs11.CKO_PUBLIC_KEY:
			results = []uint{makePublicKeyHandle(slotIdx)}
		default:
			// Unknown class — return empty
			results = nil
		}
	} else {
		// No class filter — return all objects for the slot
		results = []uint{
			makePrivateKeyHandle(slotIdx),
			makePublicKeyHandle(slotIdx),
			makeCertificateHandle(slotIdx),
		}
	}

	sess.findActive = true
	sess.findTemplate = template
	sess.findResults = results
	sess.findPos = 0
	return nil
}

func (b *InfisicalBackend) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, error) {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return nil, ErrSessionHandleInvalid
	}
	if !sess.findActive {
		return nil, ErrFindNotActive
	}

	remaining := len(sess.findResults) - sess.findPos
	if remaining <= 0 {
		return nil, nil
	}
	count := max
	if count > remaining {
		count = remaining
	}

	result := make([]pkcs11.ObjectHandle, count)
	for i := 0; i < count; i++ {
		result[i] = pkcs11.ObjectHandle(sess.findResults[sess.findPos+i])
	}
	sess.findPos += count
	return result, nil
}

func (b *InfisicalBackend) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return ErrSessionHandleInvalid
	}
	sess.findActive = false
	sess.findResults = nil
	sess.findPos = 0
	return nil
}

func (b *InfisicalBackend) GetAttributeValue(sh pkcs11.SessionHandle, obj pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	_, ok := b.sessions.get(sh)
	if !ok {
		return nil, ErrSessionHandleInvalid
	}

	objType, slotIdx := parseObjectHandle(uint(obj))
	signer, err := b.getSignerBySlot(slotIdx)
	if err != nil {
		return nil, err
	}

	// Per PKCS#11 spec, every template attribute must produce exactly one result attribute.
	result := make([]*pkcs11.Attribute, 0, len(template))

	for _, attr := range template {
		switch attr.Type {
		case pkcs11.CKA_CLASS:
			switch objType {
			case objPrivateKey:
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY))
			case objPublicKey:
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY))
			case objCertificate:
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE))
			default:
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_CLASS, []byte{}))
			}

		case pkcs11.CKA_TOKEN:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true))

		case pkcs11.CKA_PRIVATE:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, objType == objPrivateKey))

		case pkcs11.CKA_SENSITIVE:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, objType == objPrivateKey))

		case pkcs11.CKA_EXTRACTABLE:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false))

		case pkcs11.CKA_ALWAYS_AUTHENTICATE:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, false))

		case pkcs11.CKA_LABEL:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(signer.Name)))

		case pkcs11.CKA_ID:
			id := truncate(signer.ID, 20)
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(id)))

		case pkcs11.CKA_SIGN:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SIGN, objType == objPrivateKey))

		case pkcs11.CKA_KEY_TYPE:
			keyType := b.getKeyType(signer)
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType))

		case pkcs11.CKA_MODULUS:
			if (objType == objPrivateKey || objType == objPublicKey) && b.getKeyType(signer) == pkcs11.CKK_RSA {
				if pk, err := b.getPublicKeyData(signer.ID); err == nil {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_MODULUS, pk.modulus))
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{}))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{}))
			}

		case pkcs11.CKA_PUBLIC_EXPONENT:
			if (objType == objPrivateKey || objType == objPublicKey) && b.getKeyType(signer) == pkcs11.CKK_RSA {
				if pk, err := b.getPublicKeyData(signer.ID); err == nil {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pk.exponent))
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{}))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{}))
			}

		case pkcs11.CKA_MODULUS_BITS:
			if (objType == objPrivateKey || objType == objPublicKey) && b.getKeyType(signer) == pkcs11.CKK_RSA {
				if pk, err := b.getPublicKeyData(signer.ID); err == nil {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, uint(len(pk.modulus)*8)))
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, uint(0)))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, uint(0)))
			}

		case pkcs11.CKA_VALUE:
			if objType == objCertificate {
				certData, err := b.getCertificateData(signer.ID)
				if err != nil {
					b.log.Warn().Err(err).Str("signer", signer.ID).Msg("Failed to get certificate")
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{}))
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_VALUE, certData))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{}))
			}

		case pkcs11.CKA_CERTIFICATE_TYPE:
			if objType == objCertificate {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, uint(CKC_X_509)))
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, []byte{}))
			}

		case pkcs11.CKA_VERIFY:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_VERIFY, objType == objPublicKey))

		case pkcs11.CKA_ENCRYPT, pkcs11.CKA_DECRYPT, pkcs11.CKA_WRAP, pkcs11.CKA_UNWRAP,
			pkcs11.CKA_VERIFY_RECOVER, pkcs11.CKA_SIGN_RECOVER,
			pkcs11.CKA_DERIVE, pkcs11.CKA_TRUSTED, pkcs11.CKA_WRAP_WITH_TRUSTED, pkcs11.CKA_LOCAL:
			result = append(result, pkcs11.NewAttribute(attr.Type, false))

		case pkcs11.CKA_NEVER_EXTRACTABLE:
			// Private keys are never extractable (remote HSM-like)
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_NEVER_EXTRACTABLE, objType == objPrivateKey))

		case pkcs11.CKA_ALWAYS_SENSITIVE:
			result = append(result, pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_SENSITIVE, objType == objPrivateKey))

		case pkcs11.CKA_EC_PARAMS:
			if (objType == objPrivateKey || objType == objPublicKey) && b.getKeyType(signer) == pkcs11.CKK_EC {
				if ec, err := b.getECPublicKeyData(signer.ID); err == nil {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ec.ecParams))
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{}))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{}))
			}

		case pkcs11.CKA_EC_POINT:
			if (objType == objPrivateKey || objType == objPublicKey) && b.getKeyType(signer) == pkcs11.CKK_EC {
				if ec, err := b.getECPublicKeyData(signer.ID); err == nil {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ec.ecPoint))
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{}))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{}))
			}

		case pkcs11.CKA_SUBJECT:
			if objType == objCertificate {
				if certData, err := b.getCertificateData(signer.ID); err == nil {
					if cert, err := x509.ParseCertificate(certData); err == nil {
						result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject))
					} else {
						result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte{}))
					}
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte{}))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte{}))
			}

		case pkcs11.CKA_ISSUER:
			if objType == objCertificate {
				if certData, err := b.getCertificateData(signer.ID); err == nil {
					if cert, err := x509.ParseCertificate(certData); err == nil {
						result = append(result, pkcs11.NewAttribute(pkcs11.CKA_ISSUER, cert.RawIssuer))
					} else {
						result = append(result, pkcs11.NewAttribute(pkcs11.CKA_ISSUER, []byte{}))
					}
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_ISSUER, []byte{}))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_ISSUER, []byte{}))
			}

		case pkcs11.CKA_SERIAL_NUMBER:
			if objType == objCertificate {
				if certData, err := b.getCertificateData(signer.ID); err == nil {
					if cert, err := x509.ParseCertificate(certData); err == nil {
						result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, cert.SerialNumber.Bytes()))
					} else {
						result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, []byte{}))
					}
				} else {
					result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, []byte{}))
				}
			} else {
				result = append(result, pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, []byte{}))
			}

		default:
			result = append(result, pkcs11.NewAttribute(attr.Type, []byte{}))
		}
	}

	return result, nil
}

func (b *InfisicalBackend) getKeyType(signer *signerResponse) uint {
	keyAlg := signer.keyAlgorithm()
	switch {
	case strings.Contains(keyAlg, "rsa"):
		return pkcs11.CKK_RSA
	case strings.Contains(keyAlg, "ec"):
		return pkcs11.CKK_EC
	default:
		return pkcs11.CKK_RSA
	}
}

// getCertificateData fetches the DER certificate for a signer.
func (b *InfisicalBackend) getCertificateData(signerID string) ([]byte, error) {
	if data, ok := b.certCache.getCert(signerID); ok {
		return data, nil
	}

	signer, err := b.getSignerBySignerID(signerID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve signer for certificate: %w", err)
	}
	if signer.CertificateID == "" {
		return nil, fmt.Errorf("signer %s has no certificate", signer.Name)
	}

	var certResp *certBodyResponse
	err = b.withRetryOnAuth(func(token string) error {
		var callErr error
		certResp, callErr = b.client.GetCertificate(token, signer.ID)
		return callErr
	})
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(certResp.Certificate))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate from API")
	}

	b.certCache.setCert(signerID, block.Bytes)
	return block.Bytes, nil
}

// getSignerBySignerID finds a signer by its actual ID (not slot index).
func (b *InfisicalBackend) getSignerBySignerID(signerID string) (*signerResponse, error) {
	signers, err := b.getSigners()
	if err != nil {
		return nil, err
	}
	for i := range signers {
		if signers[i].ID == signerID {
			return &signers[i], nil
		}
	}
	return nil, fmt.Errorf("signer %s not found", signerID)
}

type rsaKeyData struct {
	modulus  []byte // big-endian unsigned
	exponent []byte // big-endian unsigned
}

// getPublicKeyData extracts RSA public key components from the signer's certificate.
func (b *InfisicalBackend) getPublicKeyData(signerID string) (*rsaKeyData, error) {
	if pk, ok := b.certCache.getPubKey(signerID); ok {
		return &rsaKeyData{modulus: pk.PublicKeyDER, exponent: pk.Exponent}, nil
	}

	certData, err := b.getCertificateData(signerID)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain an RSA public key")
	}

	data := &rsaKeyData{
		modulus:  rsaPub.N.Bytes(),
		exponent: big.NewInt(int64(rsaPub.E)).Bytes(),
	}

	b.certCache.setPubKey(signerID, pubKeyEntry{
		PublicKeyDER: data.modulus,
		Exponent:     data.exponent,
		Algorithm:    "RSA",
	})

	return data, nil
}

type ecKeyData struct {
	ecParams []byte // DER-encoded curve OID
	ecPoint  []byte // DER-encoded OCTET STRING of uncompressed point
}

var (
	oidP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// getECPublicKeyData extracts EC public key components from the signer's certificate.
func (b *InfisicalBackend) getECPublicKeyData(signerID string) (*ecKeyData, error) {
	if pk, ok := b.certCache.getPubKey(signerID); ok && pk.Algorithm == "EC" {
		return &ecKeyData{ecParams: pk.ECParams, ecPoint: pk.ECPoint}, nil
	}

	certData, err := b.getCertificateData(signerID)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain an EC public key")
	}

	var curveOID asn1.ObjectIdentifier
	switch ecPub.Curve {
	case elliptic.P256():
		curveOID = oidP256
	case elliptic.P384():
		curveOID = oidP384
	case elliptic.P521():
		curveOID = oidP521
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", ecPub.Curve.Params().Name)
	}

	ecParamsDER, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC params: %w", err)
	}

	// Build uncompressed EC point (0x04 || X || Y) without deprecated elliptic.Marshal.
	byteLen := (ecPub.Curve.Params().BitSize + 7) / 8
	pointBytes := make([]byte, 1+2*byteLen)
	pointBytes[0] = 0x04 // uncompressed
	ecPub.X.FillBytes(pointBytes[1 : 1+byteLen])
	ecPub.Y.FillBytes(pointBytes[1+byteLen:])
	ecPointDER, err := asn1.Marshal(pointBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC point: %w", err)
	}

	data := &ecKeyData{ecParams: ecParamsDER, ecPoint: ecPointDER}

	b.certCache.setPubKey(signerID, pubKeyEntry{
		ECParams:  data.ecParams,
		ECPoint:   data.ecPoint,
		Algorithm: "EC",
	})

	return data, nil
}

func (b *InfisicalBackend) SignInit(sh pkcs11.SessionHandle, mechanism []*pkcs11.Mechanism, key pkcs11.ObjectHandle) error {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return ErrSessionHandleInvalid
	}
	if !sess.loggedIn {
		return ErrNotLoggedIn
	}
	if sess.signActive {
		return ErrSignAlreadyActive
	}

	_, slotIdx := parseObjectHandle(uint(key))

	if len(mechanism) == 0 {
		return fmt.Errorf("no mechanism provided")
	}

	sess.signActive = true
	sess.signMech = mechanism[0].Mechanism
	sess.signKeyIndex = slotIdx
	sess.signBuffer = nil
	return nil
}

func (b *InfisicalBackend) Sign(sh pkcs11.SessionHandle, data []byte) ([]byte, error) {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return nil, ErrSessionHandleInvalid
	}
	if !sess.signActive {
		return nil, ErrSignNotActive
	}

	// Return cached signature from a previous CKR_BUFFER_TOO_SMALL retry.
	if sess.cachedSignature != nil {
		sig := sess.cachedSignature
		b.clearSignState(sess)
		return sig, nil
	}

	sig, err := b.signInternal(sess, data)
	if err != nil {
		b.clearSignState(sess)
		return nil, err
	}
	// Don't clear sign state here — main.go will clear after successful copy,
	// or cache the signature if the caller's buffer is too small.
	return sig, nil
}

// signInternal performs the actual signing logic (shared by Sign and SignFinal).
func (b *InfisicalBackend) signInternal(sess *session, data []byte) ([]byte, error) {
	signer, err := b.getSignerBySlot(sess.signKeyIndex)
	if err != nil {
		return nil, err
	}

	var algorithm string
	var signData []byte
	isDigest := true

	if sess.signMech == pkcs11.CKM_RSA_PKCS {
		alg, digest, err := parseDigestInfo(data)
		if err != nil {
			b.log.Warn().Err(err).Msg("Failed to parse DigestInfo")
			return nil, fmt.Errorf("invalid DigestInfo for CKM_RSA_PKCS")
		}
		algorithm = alg
		signData = digest
	} else if sess.signMech == pkcs11.CKM_ECDSA {
		// Raw ECDSA: data is a pre-computed hash, detect algorithm from digest length
		switch len(data) {
		case 48:
			algorithm = AlgECDSASHA384
		case 64:
			algorithm = AlgECDSASHA512
		default:
			algorithm = AlgECDSASHA256
		}
		signData = data
	} else if isPSSMechanism(sess.signMech) {
		alg, err := mechanismToAlgorithm(sess.signMech)
		if err != nil {
			return nil, err
		}
		algorithm = alg
		signData = data
		isDigest = false
	} else {
		alg, err := mechanismToAlgorithm(sess.signMech)
		if err != nil {
			return nil, err
		}
		algorithm = alg
		signData = hashDataForMechanism(sess.signMech, data)
	}

	hostname, _ := os.Hostname()

	req := signRequest{
		Data:             base64.StdEncoding.EncodeToString(signData),
		SigningAlgorithm: algorithm,
		IsDigest:         isDigest,
		ClientMetadata: map[string]interface{}{
			"tool":     fmt.Sprintf("pkcs11-module/%s", version),
			"hostname": hostname,
		},
	}

	var resp *signResponse
	err = b.withRetryOnAuth(func(token string) error {
		var callErr error
		resp, callErr = b.client.Sign(token, signer.ID, req)
		return callErr
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 403 {
			b.requestApprovalIfConfigured(signer)
		}
		b.log.Error().Err(err).Str("signer", signer.Name).Str("algorithm", algorithm).Msg("Sign failed")
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	b.log.Info().Str("signer", signer.Name).Str("algorithm", algorithm).Int("sig_bytes", len(sig)).Msg("Sign successful")
	return sig, nil
}

func (b *InfisicalBackend) requestApprovalIfConfigured(signer *signerResponse) {
	cfg := b.config.Approval
	if cfg.SigningCount == 0 && cfg.SigningDuration == "" {
		return
	}
	if signer.ApprovalPolicyID == nil || *signer.ApprovalPolicyID == "" {
		b.log.Warn().Str("signer", signer.Name).Msg("Signing requires approval but signer has no approval policy ID; cannot auto-request")
		return
	}

	req := approvalRequest{
		Justification: "Auto-requested by PKCS#11 module",
	}

	if cfg.SigningDuration != "" {
		d, err := parseDuration(cfg.SigningDuration)
		if err == nil {
			now := time.Now().UTC()
			req.RequestedWindowStart = now.Format(time.RFC3339)
			req.RequestedWindowEnd = now.Add(d).Format(time.RFC3339)
		}
	}
	if cfg.SigningCount > 0 {
		req.RequestedSignings = cfg.SigningCount
	}

	token, err := b.getToken()
	if err != nil {
		b.log.Warn().Msg("Cannot auto-request approval: no access token")
		return
	}

	result, err := b.client.RequestApproval(token, signer.ID, req)
	if err != nil {
		b.log.Warn().Err(err).Str("signer", signer.Name).Msg("Failed to auto-request signing approval")
		return
	}

	b.log.Info().
		Str("signer", signer.Name).
		Str("request_id", result.ID).
		Str("status", result.Status).
		Msg("Auto-requested signing approval (requires approver action)")
}

func (b *InfisicalBackend) EstimateSignatureSize(sh pkcs11.SessionHandle) int {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return 512 // safe default for RSA-4096
	}
	signer, err := b.getSignerBySlot(sess.signKeyIndex)
	if err != nil {
		return 512
	}
	keyAlg := signer.keyAlgorithm()
	switch {
	case strings.Contains(keyAlg, "4096"):
		return 512
	case strings.Contains(keyAlg, "3072"):
		return 384
	case strings.Contains(keyAlg, "2048"):
		return 256
	case strings.Contains(keyAlg, "ec"), strings.Contains(keyAlg, "ecdsa"):
		return 132 // P-521 max
	default:
		return 512
	}
}

func (b *InfisicalBackend) clearSignState(sess *session) {
	sess.signActive = false
	sess.signMech = 0
	sess.signKeyIndex = 0
	sess.signBuffer = nil
	sess.cachedSignature = nil
}

// clearSignStateByHandle clears signing state by session handle (convenience for main.go).
func (b *InfisicalBackend) clearSignStateByHandle(sh pkcs11.SessionHandle) {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return
	}
	b.clearSignState(sess)
}

// cacheSignResult stores a computed signature in the session for retry after CKR_BUFFER_TOO_SMALL.
// Per PKCS#11 spec, the signing operation must remain active so the caller can retry with a larger buffer.
func (b *InfisicalBackend) cacheSignResult(sh pkcs11.SessionHandle, sig []byte) {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return
	}
	sess.cachedSignature = sig
}

func (b *InfisicalBackend) SignUpdate(sh pkcs11.SessionHandle, data []byte) error {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return ErrSessionHandleInvalid
	}
	if !sess.signActive {
		return ErrSignNotActive
	}
	return sess.appendSignBuffer(data)
}

func (b *InfisicalBackend) SignFinal(sh pkcs11.SessionHandle) ([]byte, error) {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return nil, ErrSessionHandleInvalid
	}
	if !sess.signActive {
		return nil, ErrSignNotActive
	}

	// Return cached signature from a previous CKR_BUFFER_TOO_SMALL retry.
	if sess.cachedSignature != nil {
		sig := sess.cachedSignature
		b.clearSignState(sess)
		return sig, nil
	}

	sig, err := b.signInternal(sess, sess.signBuffer)
	if err != nil {
		b.clearSignState(sess)
		return nil, err
	}
	return sig, nil
}

func hashDataForMechanism(mech uint, data []byte) []byte {
	switch mech {
	case pkcs11.CKM_SHA256_RSA_PKCS, pkcs11.CKM_SHA256_RSA_PKCS_PSS, pkcs11.CKM_ECDSA_SHA256:
		h := sha256.Sum256(data)
		return h[:]
	case pkcs11.CKM_SHA384_RSA_PKCS, pkcs11.CKM_SHA384_RSA_PKCS_PSS, pkcs11.CKM_ECDSA_SHA384:
		h := sha512.Sum384(data)
		return h[:]
	case pkcs11.CKM_SHA512_RSA_PKCS, pkcs11.CKM_SHA512_RSA_PKCS_PSS, pkcs11.CKM_ECDSA_SHA512:
		h := sha512.Sum512(data)
		return h[:]
	default:
		return data
	}
}

func (b *InfisicalBackend) GetSessionInfo(sh pkcs11.SessionHandle) (pkcs11.SessionInfo, error) {
	sess, ok := b.sessions.get(sh)
	if !ok {
		return pkcs11.SessionInfo{}, ErrSessionHandleInvalid
	}

	state := uint(pkcs11.CKS_RO_PUBLIC_SESSION)
	if sess.loggedIn {
		state = uint(pkcs11.CKS_RO_USER_FUNCTIONS)
	}

	return pkcs11.SessionInfo{
		SlotID: sess.slotID,
		State:  state,
		Flags:  pkcs11.CKF_SERIAL_SESSION,
	}, nil
}

func padString(s string, length int) string {
	if len(s) >= length {
		return s[:length]
	}
	return s + strings.Repeat(" ", length-len(s))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
