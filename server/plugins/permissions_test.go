package plugins

import (
	"strings"
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestValidateManifestPermissionsAllowsValidHTTPAction(t *testing.T) {
	manifest := loadPermissionTestManifest(t, `id: claims-http
name: Claims HTTP Action
type: flow_action
permissions:
  - hook:before_token_issue
  - network:http_action
events:
  - before_token_issue
http_action:
  url: "https://actions.example.com/claims"
`)

	if err := ValidateManifestPermissions(manifest, config.PluginsConfig{}); err != nil {
		t.Fatalf("expected valid permissions to pass: %v", err)
	}
}

func TestValidateManifestPermissionsRejectsMissingHookPermission(t *testing.T) {
	manifest := loadPermissionTestManifest(t, `id: claims-http
name: Claims HTTP Action
type: flow_action
permissions:
  - network:http_action
events:
  - before_token_issue
http_action:
  url: "https://actions.example.com/claims"
`)

	err := ValidateManifestPermissions(manifest, config.PluginsConfig{})
	if err == nil || !strings.Contains(err.Error(), "hook:before_token_issue") {
		t.Fatalf("expected missing hook permission error, got %v", err)
	}
}

func TestValidateManifestPermissionsRejectsMissingNetworkPermission(t *testing.T) {
	manifest := loadPermissionTestManifest(t, `id: claims-http
name: Claims HTTP Action
type: flow_action
permissions:
  - hook:before_token_issue
events:
  - before_token_issue
http_action:
  url: "https://actions.example.com/claims"
`)

	err := ValidateManifestPermissions(manifest, config.PluginsConfig{})
	if err == nil || !strings.Contains(err.Error(), PermissionNetworkHTTPAction) {
		t.Fatalf("expected missing network permission error, got %v", err)
	}
}

func TestValidateManifestPermissionsRejectsUnknownEvent(t *testing.T) {
	manifest := loadPermissionTestManifest(t, `id: claims-http
name: Claims HTTP Action
type: flow_action
permissions:
  - hook:made_up
  - network:http_action
events:
  - made_up
http_action:
  url: "https://actions.example.com/claims"
`)

	err := ValidateManifestPermissions(manifest, config.PluginsConfig{})
	if err == nil || !strings.Contains(err.Error(), "unsupported permission") {
		t.Fatalf("expected unknown permission error, got %v", err)
	}
}

func TestValidateManifestPermissionsRejectsServerPolicy(t *testing.T) {
	manifest := loadPermissionTestManifest(t, `id: claims-http
name: Claims HTTP Action
type: flow_action
permissions:
  - hook:before_token_issue
  - network:http_action
events:
  - before_token_issue
http_action:
  url: "https://actions.example.com/claims"
`)

	err := ValidateManifestPermissions(manifest, config.PluginsConfig{
		AllowedPermissions: []string{"hook:before_token_issue"},
	})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected server policy error, got %v", err)
	}
}

func TestValidateManifestPermissionsAllowsAuditSink(t *testing.T) {
	manifest := loadPermissionTestManifest(t, `id: audit-webhook
name: Audit Webhook
type: audit_sink
permissions:
  - audit:security
  - network:audit_sink
audit_sink:
  url: "https://audit.example.com/mkauth"
`)

	if err := ValidateManifestPermissions(manifest, config.PluginsConfig{}); err != nil {
		t.Fatalf("expected valid audit sink permissions to pass: %v", err)
	}
}

func TestValidateManifestPermissionsRejectsMissingAuditSinkPermission(t *testing.T) {
	manifest := loadPermissionTestManifest(t, `id: audit-webhook
name: Audit Webhook
type: audit_sink
permissions:
  - network:audit_sink
audit_sink:
  url: "https://audit.example.com/mkauth"
`)

	err := ValidateManifestPermissions(manifest, config.PluginsConfig{})
	if err == nil || !strings.Contains(err.Error(), PermissionAuditSecurity) {
		t.Fatalf("expected missing audit security permission error, got %v", err)
	}
}

func loadPermissionTestManifest(t *testing.T, raw string) Manifest {
	t.Helper()
	manifest, err := LoadManifestContent([]byte(raw), "test-manifest.yaml")
	if err != nil {
		t.Fatalf("failed to load test manifest: %v", err)
	}
	return manifest
}
