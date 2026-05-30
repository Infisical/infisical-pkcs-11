package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	infisical "github.com/infisical/go-sdk"
)

const userAgent = "infisical-pkcs11-module"

type InfisicalClient struct {
	httpClient *resty.Client
	sdkClient  infisical.InfisicalClientInterface
	sdkConfig  infisical.Config
}

type signerResponse struct {
	ID                      string  `json:"id"`
	Name                    string  `json:"name"`
	Status                  string  `json:"status"`
	CertificateID           string  `json:"certificateId"`
	CertificateKeyAlgorithm *string `json:"certificateKeyAlgorithm"`
	ApprovalPolicyID        *string `json:"approvalPolicyId"`
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

	var caCertPEM string
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
		caCertPEM = string(caCert)
	}

	httpClient := resty.New().
		SetBaseURL(cfg.ServerURL).
		SetTLSClientConfig(tlsCfg).
		SetTimeout(30*time.Second).
		SetHeader("User-Agent", userAgent)

	sdkCfg := infisical.Config{
		SiteUrl:       strings.TrimRight(cfg.ServerURL, "/"),
		CaCertificate: caCertPEM,
		UserAgent:     userAgent,
		SilentMode:    true,
	}

	return &InfisicalClient{
		httpClient: httpClient,
		sdkConfig:  sdkCfg,
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

func (c *InfisicalClient) ensureSDKClient() {
	if c.sdkClient == nil {
		c.sdkClient = infisical.NewInfisicalClient(context.Background(), c.sdkConfig)
	}
}

func (c *InfisicalClient) UniversalAuthLogin(clientID, clientSecret string) error {
	c.ensureSDKClient()
	_, err := c.sdkClient.Auth().UniversalAuthLogin(clientID, clientSecret)
	if err != nil {
		return &RequestError{Operation: "login", Err: err}
	}
	return nil
}

func (c *InfisicalClient) GetAccessToken() string {
	if c.sdkClient == nil {
		return ""
	}
	return c.sdkClient.Auth().GetAccessToken()
}

func (c *InfisicalClient) ListSigners(token string) ([]signerResponse, error) {
	const operation = "list-signers"

	var result listSignersResponse
	resp, err := c.httpClient.R().
		SetAuthToken(token).
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

type signerCertResponse struct {
	CertificatePem string `json:"certificatePem"`
	SignerName     string `json:"signerName"`
}

func (c *InfisicalClient) GetCertificate(token, signerID string) (*certBodyResponse, error) {
	const operation = "get-certificate"

	var raw signerCertResponse
	resp, err := c.httpClient.R().
		SetAuthToken(token).
		SetResult(&raw).
		Get(fmt.Sprintf("/api/v1/cert-manager/signers/%s/certificate", signerID))

	if err != nil {
		return nil, &RequestError{Operation: operation, Err: err}
	}
	if resp.IsError() {
		return nil, NewAPIError(operation, resp.StatusCode(), parseErrorResponse(resp))
	}

	return &certBodyResponse{Certificate: raw.CertificatePem}, nil
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

type approvalRequest struct {
	Justification        string `json:"justification"`
	RequestedSignings    int    `json:"requestedSignings,omitempty"`
	RequestedWindowStart string `json:"requestedWindowStart,omitempty"`
	RequestedWindowEnd   string `json:"requestedWindowEnd,omitempty"`
}

type approvalRequestResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (c *InfisicalClient) RequestApproval(token, signerID string, req approvalRequest) (*approvalRequestResponse, error) {
	const operation = "request-approval"

	var result approvalRequestResponse
	resp, err := c.httpClient.R().
		SetAuthToken(token).
		SetBody(req).
		SetResult(&result).
		Post(fmt.Sprintf("/api/v1/cert-manager/signers/%s/requests", signerID))

	if err != nil {
		return nil, &RequestError{Operation: operation, Err: err}
	}
	if resp.IsError() {
		return nil, NewAPIError(operation, resp.StatusCode(), parseErrorResponse(resp))
	}

	return &result, nil
}
