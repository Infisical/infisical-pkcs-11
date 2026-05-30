package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "pkcs11.conf")

	configJSON := `{
		"server_url": "https://app.infisical.com",
		"auth": {
			"method": "universal-auth",
			"client_id": "test-id",
			"client_secret": "test-secret"
		},
		"tls": {
			"skip_verify": false
		},
		"cache": {
			"token_ttl_seconds": 600,
			"cert_ttl_seconds": 7200
		},
		"log_level": "debug"
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(envConfigPath, configPath)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ServerURL != "https://app.infisical.com" {
		t.Errorf("expected server_url https://app.infisical.com, got %s", cfg.ServerURL)
	}
	if cfg.Auth.ClientID != "test-id" {
		t.Errorf("expected client_id test-id, got %s", cfg.Auth.ClientID)
	}
	if cfg.Cache.TokenTTLSeconds != 600 {
		t.Errorf("expected token_ttl_seconds 600, got %d", cfg.Cache.TokenTTLSeconds)
	}
	if cfg.Cache.CertTTLSeconds != 7200 {
		t.Errorf("expected cert_ttl_seconds 7200, got %d", cfg.Cache.CertTTLSeconds)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected log_level debug, got %s", cfg.LogLevel)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "pkcs11.conf")

	configJSON := `{
		"server_url": "https://app.infisical.com"
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(envConfigPath, configPath)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Cache.TokenTTLSeconds != 300 {
		t.Errorf("expected default token_ttl_seconds 300, got %d", cfg.Cache.TokenTTLSeconds)
	}
	if cfg.Cache.CertTTLSeconds != 3600 {
		t.Errorf("expected default cert_ttl_seconds 3600, got %d", cfg.Cache.CertTTLSeconds)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default log_level info, got %s", cfg.LogLevel)
	}
	if cfg.Auth.Method != "universal-auth" {
		t.Errorf("expected default auth method universal-auth, got %s", cfg.Auth.Method)
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "pkcs11.conf")

	configJSON := `{
		"server_url": "https://app.infisical.com",
		"auth": {
			"client_id": "config-id",
			"client_secret": "config-secret"
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(envConfigPath, configPath)
	t.Setenv(envClientID, "env-id")
	t.Setenv(envSecret, "env-secret")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Auth.ClientID != "env-id" {
		t.Errorf("expected env override client_id 'env-id', got %s", cfg.Auth.ClientID)
	}
	if cfg.Auth.ClientSecret != "env-secret" {
		t.Errorf("expected env override client_secret 'env-secret', got %s", cfg.Auth.ClientSecret)
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "pkcs11.conf")

	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name:    "missing server_url",
			config:  `{}`,
			wantErr: true,
		},
		{
			name:    "unsupported auth method",
			config:  `{"server_url": "https://app.infisical.com", "auth": {"method": "oauth"}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(configPath, []byte(tt.config), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(envConfigPath, configPath)

			_, err := loadConfig()
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
