package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

const userAgent = "infisical-pkcs11-module"

type InfisicalClient struct {
	httpClient *resty.Client
}

type loginRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type loginResponse struct {
	AccessToken    string `json:"accessToken"`
	ExpiresIn      int    `json:"expiresIn"`
	AccessTokenTTL int    `json:"accessTokenTTL"`
}

type signerResponse struct {
	ID                      string  `json:"id"`
	Name                    string  `json:"name"`
	CertificateID           string  `json:"certificateId"`
	CertificateKeyAlgorithm *string `json:"certificateKeyAlgorithm"`
}

func (s *signerResponse) keyAlgorithm() string {
	if s.CertificateKeyAlgorithm != nil {
		return strings.ToLower(*s.CertificateKeyAlgorithm)
	}
	return ""
}

type listSignersResponse struct {
	Signers []signerResponse `json:"signers"`
}

type signRequest struct {
	Data             string                 `json:"data"`
	SigningAlgorithm string                 `json:"signingAlgorithm"`
	IsDigest         bool                   `json:"isDigest"`
	ClientMetadata   map[string]interface{} `json:"clientMetadata,omitempty"`
}

type signResponse struct {
	Signature string `json:"signature"`
}

type apiErrorBody struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

func newInfisicalClient(cfg *Config) (*InfisicalClient, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.TLS.SkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}

	if cfg.TLS.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.TLS.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", cfg.TLS.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	client := resty.New().
		SetBaseURL(cfg.ServerURL).
		SetTLSClientConfig(tlsCfg).
		SetTimeout(30*time.Second).
		SetHeader("User-Agent", userAgent)

	return &InfisicalClient{
		httpClient: client,
	}, nil
}

func parseErrorResponse(resp *resty.Response) string {
	var body apiErrorBody
	if err := json.Unmarshal(resp.Body(), &body); err == nil {
		if body.Message != "" {
			return body.Message
		}
		if body.Error != "" {
			return body.Error
		}
	}
	return fmt.Sprintf("HTTP %d", resp.StatusCode())
}

func (c *InfisicalClient) Login(clientID, clientSecret string) (*loginResponse, error) {
	const operation = "login"

	var result loginResponse
	resp, err := c.httpClient.R().
		SetBody(loginRequest{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}).
		SetResult(&result).
		Post("/api/v1/auth/universal-auth/login")

	if err != nil {
		return nil, &RequestError{Operation: operation, Err: err}
	}
	if resp.IsError() {
		return nil, NewAPIError(operation, resp.StatusCode(), parseErrorResponse(resp))
	}

	return &result, nil
}

func (c *InfisicalClient) ListSigners(token, projectID string) ([]signerResponse, error) {
	const operation = "list-signers"

	var result listSignersResponse
	resp, err := c.httpClient.R().
		SetAuthToken(token).
		SetQueryParam("projectId", projectID).
		SetQueryParam("limit", "100").
		SetResult(&result).
		Get("/api/v1/cert-manager/signers")

	if err != nil {
		return nil, &RequestError{Operation: operation, Err: err}
	}
	if resp.IsError() {
		return nil, NewAPIError(operation, resp.StatusCode(), parseErrorResponse(resp))
	}

	return result.Signers, nil
}

type certBodyResponse struct {
	Certificate string `json:"certificate"`
}

// GetCertificate fetches the PEM certificate body using the certificate ID
// (from the signer's certificateId field, not the signer ID).
func (c *InfisicalClient) GetCertificate(token, certificateID string) (*certBodyResponse, error) {
	const operation = "get-certificate"

	var result certBodyResponse
	resp, err := c.httpClient.R().
		SetAuthToken(token).
		SetResult(&result).
		Get(fmt.Sprintf("/api/v1/cert-manager/certificates/%s/certificate", certificateID))

	if err != nil {
		return nil, &RequestError{Operation: operation, Err: err}
	}
	if resp.IsError() {
		return nil, NewAPIError(operation, resp.StatusCode(), parseErrorResponse(resp))
	}

	return &result, nil
}

func (c *InfisicalClient) Sign(token, signerID string, req signRequest) (*signResponse, error) {
	const operation = "sign"

	var result signResponse
	resp, err := c.httpClient.R().
		SetAuthToken(token).
		SetBody(req).
		SetResult(&result).
		Post(fmt.Sprintf("/api/v1/cert-manager/signers/%s/sign", signerID))

	if err != nil {
		return nil, &RequestError{Operation: operation, Err: err}
	}
	if resp.IsError() {
		return nil, NewAPIError(operation, resp.StatusCode(), parseErrorResponse(resp))
	}

	return &result, nil
}
