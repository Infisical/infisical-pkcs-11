package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	envConfigPath = "INFISICAL_PKCS11_CONFIG"
	envClientID   = "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"
	envSecret     = "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"
	envServerURL  = "INFISICAL_PKCS11_SERVER_URL"

	defaultConfigPath = "/etc/infisical/pkcs11.conf"
)

type TLSConfig struct {
	CACertPath string `json:"ca_cert_path"`
	SkipVerify bool   `json:"skip_verify"`
}

type CacheConfig struct {
	TokenTTLSeconds  int `json:"token_ttl_seconds"`
	CertTTLSeconds   int `json:"cert_ttl_seconds"`
	SignerTTLSeconds int `json:"signer_ttl_seconds"`
}

type AuthConfig struct {
	Method       string `json:"method"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type ApprovalConfig struct {
	SigningCount    int    `json:"signing_count"`
	SigningDuration string `json:"signing_duration"`
}

type Config struct {
	ServerURL string         `json:"server_url"`
	Auth      AuthConfig     `json:"auth"`
	TLS       TLSConfig      `json:"tls"`
	Cache     CacheConfig    `json:"cache"`
	Approval  ApprovalConfig `json:"approval"`
	LogLevel  string         `json:"log_level"`
	LogFile   string         `json:"log_file"`
}

func (c *Config) setDefaults() {
	if c.Cache.TokenTTLSeconds == 0 {
		c.Cache.TokenTTLSeconds = 300
	}
	if c.Cache.CertTTLSeconds == 0 {
		c.Cache.CertTTLSeconds = 3600
	}
	if c.Cache.SignerTTLSeconds == 0 {
		c.Cache.SignerTTLSeconds = 300
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
}

// applyEnvOverrides applies environment variable overrides.
func (c *Config) applyEnvOverrides() {
	if v := os.Getenv(envServerURL); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv(envClientID); v != "" {
		c.Auth.ClientID = v
	}
	if v := os.Getenv(envSecret); v != "" {
		c.Auth.ClientSecret = v
	}
}

func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func (c *Config) validate() error {
	if c.ServerURL == "" {
		return fmt.Errorf("server_url is required")
	}
	if c.Auth.Method == "" {
		c.Auth.Method = "universal-auth"
	}
	if c.Auth.Method != "universal-auth" {
		return fmt.Errorf("unsupported auth method: %s (must be 'universal-auth')", c.Auth.Method)
	}
	if c.Approval.SigningDuration != "" {
		d, err := parseDuration(c.Approval.SigningDuration)
		if err != nil {
			return fmt.Errorf("invalid approval.signing_duration: %w", err)
		}
		if d < time.Minute || d > 30*24*time.Hour {
			return fmt.Errorf("approval.signing_duration must be between 1m and 30d")
		}
	}
	if c.Approval.SigningCount < 0 {
		return fmt.Errorf("approval.signing_count must be a positive integer")
	}
	return nil
}

func loadConfig() (*Config, error) {
	path := os.Getenv(envConfigPath)
	if path == "" {
		path = defaultConfigPath
	}

	// Check file permissions on Unix systems (warn if world-readable)
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err == nil {
			perm := info.Mode().Perm()
			if perm&0o044 != 0 {
				fmt.Fprintf(os.Stderr, "[infisical-pkcs11] WARNING: config file %s has permissions %04o — "+
					"this file may contain credentials, consider: chmod 600 %s\n", path, perm, path)
			}
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	cfg.setDefaults()
	cfg.applyEnvOverrides()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}
