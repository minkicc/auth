package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("AUTH_TEST_ISSUER", "https://auth.example.org")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("oidc:\n  issuer: ${AUTH_TEST_ISSUER}\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.OIDC.Issuer != "https://auth.example.org" {
		t.Fatalf("environment variable was not expanded: %q", cfg.OIDC.Issuer)
	}
}
