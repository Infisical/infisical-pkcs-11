package main

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestLoadConfigTokenAuthFromFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "pkcs11.conf")
	configJSON := `{"server_url":"https://app.infisical.com","auth":{"method":"token","token":"jwt-abc"}}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envConfigPath, configPath)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Auth.Method != authMethodToken || cfg.Auth.Token != "jwt-abc" {
		t.Errorf("token auth not loaded: %+v", cfg.Auth)
	}
}

func TestLoadConfigTokenInferredFromTokenField(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "pkcs11.conf")
	// No auth.method set: a token in the config should select token auth on its own.
	configJSON := `{"server_url":"https://app.infisical.com","auth":{"token":"jwt-abc"}}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envConfigPath, configPath)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Auth.Method != authMethodToken {
		t.Errorf("token in config should infer token auth, got method %q", cfg.Auth.Method)
	}
}

func TestLoadConfigTokenEnvSelectsTokenAuth(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "pkcs11.conf")
	if err := os.WriteFile(configPath, []byte(`{"server_url":"https://app.infisical.com"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envConfigPath, configPath)
	t.Setenv(envToken, "jwt-from-env")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Auth.Method != authMethodToken {
		t.Errorf("env token should select token auth, got method %q", cfg.Auth.Method)
	}
	if cfg.Auth.Token != "jwt-from-env" {
		t.Errorf("token from env = %q", cfg.Auth.Token)
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
		{
			name:    "rejects non-http(s) scheme",
			config:  `{"server_url": "file:///etc/passwd"}`,
			wantErr: true,
		},
		{
			name:    "rejects bare path without scheme",
			config:  `{"server_url": "app.infisical.com"}`,
			wantErr: true,
		},
		{
			name:    "accepts http for local dev",
			config:  `{"server_url": "http://localhost:8080"}`,
			wantErr: false,
		},
		{
			name:    "accepts https",
			config:  `{"server_url": "https://app.infisical.com"}`,
			wantErr: false,
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

func TestDefaultConfigPathFor(t *testing.T) {
	cases := []struct {
		name        string
		goos        string
		programData string
		want        string
	}{
		{"linux", "linux", "", unixDefaultConfigPath},
		{"darwin", "darwin", `C:\ProgramData`, unixDefaultConfigPath},
		{"windows", "windows", `D:\Data`, `D:\Data\Infisical\pkcs11.conf`},
		{"windows without ProgramData set", "windows", "", `C:\ProgramData\Infisical\pkcs11.conf`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := defaultConfigPathFor(c.goos, c.programData); got != c.want {
				t.Fatalf("defaultConfigPathFor(%q, %q) = %q, want %q", c.goos, c.programData, got, c.want)
			}
		})
	}

	if got := defaultConfigPath(); got != defaultConfigPathFor(runtime.GOOS, os.Getenv("ProgramData")) {
		t.Fatalf("defaultConfigPath() disagrees with defaultConfigPathFor: %q", got)
	}
}
