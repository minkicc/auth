package plugins

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

func TestRuntimeUpdatesPluginConfigAndReloadsHook(t *testing.T) {
	actionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(iam.HTTPActionResponse{
			Claims: map[string]any{"configured": true},
		})
	}))
	defer actionServer.Close()

	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:              true,
		Directories:          []string{dir},
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	archive := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": configurableClaimsHTTPManifest("https://actions.example.com/claims"),
	})
	if _, err := runtime.InstallZip("claims-http.zip", archive, false); err != nil {
		t.Fatalf("failed to install plugin: %v", err)
	}
	view, err := runtime.SetConfigWithActor("claims-http", map[string]string{
		"url":        actionServer.URL,
		"timeout_ms": "1000",
		"secret":     "super-secret",
	}, AuditActor{ID: "admin"})
	if err != nil {
		t.Fatalf("failed to set plugin config: %v", err)
	}
	if view.Values["secret"] != "" || !view.Configured["secret"] {
		t.Fatalf("expected sensitive config to be hidden but marked configured, got %#v", view)
	}

	data := &iam.HookContext{
		User:   &auth.User{UserID: "usr_test"},
		Claims: map[string]any{"sub": "usr_test"},
	}
	if err := runtime.Hooks().Run(context.Background(), iam.HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run configured hook: %v", err)
	}
	if data.Claims["configured"] != true {
		t.Fatalf("expected configured hook to enrich claims, got %#v", data.Claims)
	}
}

func TestRuntimeRejectsUnsupportedPluginConfig(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:     true,
		Directories: []string{dir},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	archive := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": configurableClaimsHTTPManifest("https://actions.example.com/claims"),
	})
	if _, err := runtime.InstallZip("claims-http.zip", archive, false); err != nil {
		t.Fatalf("failed to install plugin: %v", err)
	}
	if _, err := runtime.SetConfig("claims-http", map[string]string{"unknown": "value"}); err == nil {
		t.Fatalf("expected unknown config key to be rejected")
	}
	if _, err := runtime.SetConfig("claims-http", map[string]string{"timeout_ms": "slow"}); err == nil {
		t.Fatalf("expected invalid integer config to be rejected")
	}
}

func TestRuntimeReplacePreservesConfigAndEnabledState(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:              true,
		Directories:          []string{dir},
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	archiveV1 := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": configurableClaimsHTTPManifest("https://actions.example.com/claims"),
	})
	if _, err := runtime.InstallZip("claims-http-v1.zip", archiveV1, false); err != nil {
		t.Fatalf("failed to install plugin v1: %v", err)
	}
	if _, err := runtime.SetConfig("claims-http", map[string]string{
		"url":        "https://actions.example.com/configured",
		"timeout_ms": "2500",
		"secret":     "keep-me",
	}); err != nil {
		t.Fatalf("failed to set plugin config: %v", err)
	}
	if _, err := runtime.SetEnabled("claims-http", false); err != nil {
		t.Fatalf("failed to disable plugin: %v", err)
	}

	manifestV2 := strings.Replace(configurableClaimsHTTPManifest("https://actions.example.com/claims"), "version: 0.1.0", "version: 0.2.0", 1)
	archiveV2 := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": manifestV2,
	})
	summary, err := runtime.InstallZip("claims-http-v2.zip", archiveV2, true)
	if err != nil {
		t.Fatalf("failed to replace plugin: %v", err)
	}
	if summary.Enabled {
		t.Fatalf("expected replace to preserve disabled state, got %#v", summary)
	}
	if summary.Version != "0.2.0" {
		t.Fatalf("expected plugin version to update, got %#v", summary)
	}
	state, err := LoadState(filepath.Join(dir, "claims-http"))
	if err != nil {
		t.Fatalf("failed to load plugin state: %v", err)
	}
	if state == nil || state.Enabled == nil || *state.Enabled {
		t.Fatalf("expected disabled state to be preserved, got %#v", state)
	}
	if state.Config["url"] != "https://actions.example.com/configured" || state.Config["timeout_ms"] != "2500" || state.Config["secret"] != "keep-me" {
		t.Fatalf("expected config to be preserved, got %#v", state.Config)
	}
}

func TestUndeclaredStateConfigDoesNotOverrideManifest(t *testing.T) {
	manifest, err := LoadManifestContent([]byte(claimsHTTPManifest("https://actions.example.com/claims")), "manifest.yaml")
	if err != nil {
		t.Fatalf("failed to load manifest: %v", err)
	}
	state := &State{Config: map[string]string{
		"url":        "https://evil.example.com/claims",
		"timeout_ms": "1",
	}}
	action := httpActionConfigFromManifest(manifest, state)
	if action.URL != "https://actions.example.com/claims" {
		t.Fatalf("expected undeclared state url to be ignored, got %q", action.URL)
	}
	if hasConfiguredPluginConfig(manifest, state) {
		t.Fatalf("expected undeclared state config to not mark plugin configured")
	}
}

func configurableClaimsHTTPManifest(actionURL string) string {
	return strings.Replace(claimsHTTPManifest(actionURL), "events:\n", "config_schema:\n"+
		"  - key: url\n"+
		"    label: URL\n"+
		"    type: url\n"+
		"    required: true\n"+
		"  - key: timeout_ms\n"+
		"    label: Timeout\n"+
		"    type: integer\n"+
		"    default: \"3000\"\n"+
		"  - key: secret\n"+
		"    label: Secret\n"+
		"    type: secret\n"+
		"events:\n", 1)
}
