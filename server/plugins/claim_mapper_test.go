package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

func TestRuntimeLoadsLocalClaimMapperPlugin(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "tenant-claims")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("failed to create plugin directory: %v", err)
	}
	manifest := `id: tenant-claims
name: Tenant Claims
version: 0.1.0
type: claim_mapper
permissions:
  - hook:before_token_issue
events:
  - before_token_issue
config_schema:
  - key: tenant_prefix
    type: string
    default: tenant
claim_mappings:
  - claim: tenant
    value: "${config.tenant_prefix}:${claim.org_slug}:${user.username}:${client_id}"
    clients:
      - demo-spa
    organizations:
      - acme
  - claim: roles_copy
    value_from: claim.org_roles
`
	if err := os.WriteFile(filepath.Join(pluginDir, "mkauth-plugin.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("failed to write plugin manifest: %v", err)
	}

	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:     true,
		Directories: []string{dir},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	data := &iam.HookContext{
		User:     &auth.User{UserID: "usr_test", Username: "alice", Status: auth.UserStatusActive},
		ClientID: "demo-spa",
		Claims: map[string]any{
			"org_slug":  "acme",
			"org_roles": []string{"admin", "billing"},
		},
	}
	if err := runtime.Hooks().Run(context.Background(), iam.HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run claim mapper hook: %v", err)
	}

	if data.Claims["tenant"] != "tenant:acme:alice:demo-spa" {
		t.Fatalf("unexpected tenant claim: %#v", data.Claims["tenant"])
	}
	roles, ok := data.Claims["roles_copy"].([]string)
	if !ok || len(roles) != 2 || roles[0] != "admin" || roles[1] != "billing" {
		t.Fatalf("unexpected roles_copy claim: %#v", data.Claims["roles_copy"])
	}
}

func TestClaimMapperSkipsNonMatchingClient(t *testing.T) {
	manifest, err := LoadManifestContent([]byte(`id: tenant-claims
name: Tenant Claims
version: 0.1.0
type: claim_mapper
permissions:
  - hook:before_token_issue
events:
  - before_token_issue
claim_mappings:
  - claim: tenant
    value: acme
    clients:
      - demo-spa
`), "test.yaml")
	if err != nil {
		t.Fatalf("failed to load manifest: %v", err)
	}
	hook, err := buildClaimMapperHook(manifest, nil)
	if err != nil {
		t.Fatalf("failed to build hook: %v", err)
	}
	data := &iam.HookContext{ClientID: "other-client", Claims: map[string]any{}}
	if err := hook.Handle(context.Background(), iam.HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run hook: %v", err)
	}
	if _, ok := data.Claims["tenant"]; ok {
		t.Fatalf("expected claim mapper to skip non-matching client, got %#v", data.Claims)
	}
}

func TestClaimMapperRejectsProtectedClaims(t *testing.T) {
	_, err := LoadManifestContent([]byte(`id: bad-claims
name: Bad Claims
version: 0.1.0
type: claim_mapper
permissions:
  - hook:before_token_issue
events:
  - before_token_issue
claim_mappings:
  - claim: sub
    value: attacker
`), "test.yaml")
	if err == nil || !strings.Contains(err.Error(), "protected claim") {
		t.Fatalf("expected protected claim error, got %v", err)
	}
}
