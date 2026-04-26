package plugins

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

func TestRuntimeInstallsVerifiedSignedPluginAndRunsHooks(t *testing.T) {
	actionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload iam.HTTPActionRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode hook request: %v", err)
		}
		if payload.PluginID != "claims-http" || payload.Event != iam.HookBeforeTokenIssue {
			t.Fatalf("unexpected hook payload: %#v", payload)
		}
		_ = json.NewEncoder(w).Encode(iam.HTTPActionResponse{
			Claims: map[string]any{"department": "engineering"},
		})
	}))
	defer actionServer.Close()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	manifestPath := "claims-http/mkauth-plugin.yaml"
	manifest := claimsHTTPManifest(actionServer.URL)
	signature := signManifest(t, privateKey, manifest)

	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:              true,
		Directories:          []string{dir},
		RequireSignature:     true,
		AllowPrivateNetworks: true,
		TrustedSigners: []config.PluginSignerConfig{{
			ID:        "test-signer",
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		}},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	archive := buildPluginArchive(t, map[string]string{
		manifestPath:                    manifest,
		"claims-http/mkauth-plugin.sig": signature,
		"claims-http/README.md":         "# claims action\n",
	})

	summary, err := runtime.InstallZip("claims-http.zip", archive, false)
	if err != nil {
		t.Fatalf("failed to install plugin: %v", err)
	}
	if summary.ID != "claims-http" || !summary.Enabled {
		t.Fatalf("unexpected installed plugin summary: %#v", summary)
	}
	if !summary.SignatureVerified || summary.SignerKeyID != "test-signer" || summary.PackageSHA256 == "" {
		t.Fatalf("expected verified signed plugin summary, got %#v", summary)
	}

	data := &iam.HookContext{
		User:   &auth.User{UserID: "usr_test"},
		Claims: map[string]any{"sub": "usr_test"},
	}
	if err := runtime.Hooks().Run(context.Background(), iam.HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run plugin hook: %v", err)
	}
	if data.Claims["department"] != "engineering" {
		t.Fatalf("expected hook to enrich claims, got %#v", data.Claims)
	}

	summary, err = runtime.SetEnabled("claims-http", false)
	if err != nil {
		t.Fatalf("failed to disable plugin: %v", err)
	}
	if summary.Enabled {
		t.Fatalf("expected plugin to be disabled, got %#v", summary)
	}

	disabledData := &iam.HookContext{
		User:   &auth.User{UserID: "usr_test"},
		Claims: map[string]any{"sub": "usr_test"},
	}
	if err := runtime.Hooks().Run(context.Background(), iam.HookBeforeTokenIssue, disabledData); err != nil {
		t.Fatalf("disabled plugin should not fail hook execution: %v", err)
	}
	if _, ok := disabledData.Claims["department"]; ok {
		t.Fatalf("expected disabled plugin not to enrich claims, got %#v", disabledData.Claims)
	}

	if err := runtime.Uninstall("claims-http"); err != nil {
		t.Fatalf("failed to uninstall plugin: %v", err)
	}
	if plugins := runtime.List(); len(plugins) != 0 {
		t.Fatalf("expected no plugins after uninstall, got %#v", plugins)
	}
}

func TestRuntimeRejectsUnsignedPluginWhenSignatureRequired(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:          true,
		Directories:      []string{dir},
		RequireSignature: true,
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	archive := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": claimsHTTPManifest("https://actions.example.com/claims"),
	})

	if _, err := runtime.InstallZip("claims-http.zip", archive, false); err == nil {
		t.Fatalf("expected unsigned plugin install to fail when signatures are required")
	}
}

func TestRuntimeRetainsRegisteredHooksAfterReload(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:     true,
		Directories: []string{dir},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	if err := runtime.RegisterHook(iam.HookFunc{
		HookName: "static-test-hook",
		Fn: func(_ context.Context, _ iam.HookEvent, data *iam.HookContext) error {
			if data.Claims == nil {
				data.Claims = map[string]any{}
			}
			data.Claims["static_hook"] = true
			return nil
		},
	}); err != nil {
		t.Fatalf("failed to register static hook: %v", err)
	}
	if err := runtime.Reload(); err != nil {
		t.Fatalf("failed to reload runtime: %v", err)
	}

	data := &iam.HookContext{Claims: map[string]any{}}
	if err := runtime.Hooks().Run(context.Background(), iam.HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run hooks: %v", err)
	}
	if data.Claims["static_hook"] != true {
		t.Fatalf("expected registered static hook to survive reload, got %#v", data.Claims)
	}
}

func TestRuntimeLoadsLocalAuditSinkPlugin(t *testing.T) {
	received := make(chan SecurityAuditSinkEvent, 1)
	sinkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sink-secret" {
			t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
		}
		var payload struct {
			PluginID string                 `json:"plugin_id"`
			Event    string                 `json:"event"`
			Audit    SecurityAuditSinkEvent `json:"audit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode audit sink payload: %v", err)
		}
		if payload.PluginID != "audit-webhook" || payload.Event != "security_audit" {
			t.Fatalf("unexpected audit sink payload envelope: %#v", payload)
		}
		received <- payload.Audit
		w.WriteHeader(http.StatusNoContent)
	}))
	defer sinkServer.Close()

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "audit-webhook")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("failed to create plugin dir: %v", err)
	}
	manifest := `id: audit-webhook
name: Audit Webhook
version: 0.1.0
type: audit_sink
permissions:
  - audit:security
  - network:audit_sink
audit_sink:
  url: "` + sinkServer.URL + `/events"
  secret: sink-secret
  actions:
    - oidc_client_create
  resource_types:
    - oidc_client
`
	if err := os.WriteFile(filepath.Join(pluginDir, "mkauth-plugin.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:              true,
		Directories:          []string{dir},
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	err = runtime.DispatchSecurityAudit(context.Background(), SecurityAuditSinkEvent{
		ID:      "aud_test",
		Time:    "2026-04-26T00:00:00Z",
		Action:  "oidc_client_create",
		Success: true,
		Details: map[string]string{"resource_type": "oidc_client", "client_id": "demo"},
	})
	if err != nil {
		t.Fatalf("failed to dispatch security audit: %v", err)
	}
	var got SecurityAuditSinkEvent
	select {
	case got = <-received:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for audit sink event")
	}
	if got.ID != "aud_test" || got.Action != "oidc_client_create" || got.Details["client_id"] != "demo" {
		t.Fatalf("unexpected received audit event: %#v", got)
	}

	if err := runtime.DispatchSecurityAudit(context.Background(), SecurityAuditSinkEvent{
		ID:      "aud_skip",
		Action:  "identity_provider_create",
		Success: true,
		Details: map[string]string{"resource_type": "identity_provider"},
	}); err != nil {
		t.Fatalf("non-matching audit event should not fail dispatch: %v", err)
	}
	select {
	case skipped := <-received:
		t.Fatalf("expected non-matching audit event to be skipped, got %#v", skipped)
	default:
	}
}

func TestRuntimeAuditSinkCanReceiveLifecycleEvents(t *testing.T) {
	received := make(chan LifecycleSinkEvent, 1)
	sinkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-MKAuth-Audit-Event") != "lifecycle" {
			t.Fatalf("unexpected audit event header: %q", r.Header.Get("X-MKAuth-Audit-Event"))
		}
		var payload struct {
			PluginID  string             `json:"plugin_id"`
			Event     string             `json:"event"`
			Lifecycle LifecycleSinkEvent `json:"lifecycle"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode lifecycle sink payload: %v", err)
		}
		if payload.PluginID != "lifecycle-webhook" || payload.Event != "lifecycle" {
			t.Fatalf("unexpected lifecycle sink payload envelope: %#v", payload)
		}
		received <- payload.Lifecycle
		w.WriteHeader(http.StatusNoContent)
	}))
	defer sinkServer.Close()

	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "lifecycle-webhook")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("failed to create plugin dir: %v", err)
	}
	manifest := `id: lifecycle-webhook
name: Lifecycle Webhook
version: 0.1.0
type: audit_sink
permissions:
  - audit:security
  - network:audit_sink
audit_sink:
  url: "` + sinkServer.URL + `/events"
  actions:
    - pre_authenticate
  resource_types:
    - auth_lifecycle
`
	if err := os.WriteFile(filepath.Join(pluginDir, "mkauth-plugin.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:              true,
		Directories:          []string{dir},
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	err = runtime.Hooks().Run(context.Background(), iam.HookPreAuthenticate, &iam.HookContext{
		User:      &auth.User{UserID: "usr_lifecycle"},
		Provider:  "enterprise_oidc",
		IP:        "203.0.113.1",
		UserAgent: "runtime-test",
		Metadata:  map[string]string{"provider_slug": "acme"},
	})
	if err != nil {
		t.Fatalf("failed to run lifecycle hook: %v", err)
	}
	var got LifecycleSinkEvent
	select {
	case got = <-received:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for lifecycle sink event")
	}
	if got.Event != "pre_authenticate" || got.UserID != "usr_lifecycle" || got.Provider != "enterprise_oidc" || got.Metadata["provider_slug"] != "acme" {
		t.Fatalf("unexpected lifecycle event: %#v", got)
	}

	if err := runtime.Hooks().Run(context.Background(), iam.HookPostLogout, &iam.HookContext{Provider: "browser_session"}); err != nil {
		t.Fatalf("non-matching lifecycle event should not fail: %v", err)
	}
	select {
	case skipped := <-received:
		t.Fatalf("expected non-matching lifecycle event to be skipped, got %#v", skipped)
	default:
	}
}

func TestRuntimeReloadRejectsTamperedSignedPlugin(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	manifest := claimsHTTPManifest("https://actions.example.com/claims")
	signature := signManifest(t, privateKey, manifest)

	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:     true,
		Directories: []string{dir},
		TrustedSigners: []config.PluginSignerConfig{{
			ID:        "test-signer",
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		}},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	archive := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": manifest,
		"claims-http/mkauth-plugin.sig":  signature,
	})

	if _, err := runtime.InstallZip("claims-http.zip", archive, false); err != nil {
		t.Fatalf("failed to install signed plugin: %v", err)
	}

	pluginDir := filepath.Join(dir, "claims-http")
	tamperedManifest := []byte(claimsHTTPManifest("https://evil.example.com/claims"))
	if err := os.WriteFile(filepath.Join(pluginDir, "mkauth-plugin.yaml"), tamperedManifest, 0o644); err != nil {
		t.Fatalf("failed to tamper manifest: %v", err)
	}

	if err := runtime.Reload(); err == nil {
		t.Fatalf("expected tampered plugin reload to fail")
	}
}

func TestRuntimeInstallsPluginFromURLWithChecksum(t *testing.T) {
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
		"claims-http/mkauth-plugin.yaml": claimsHTTPManifest("https://actions.example.com/claims"),
	})
	checksum := sha256Hex(archive)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="claims-http.zip"`)
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	summary, err := runtime.InstallURL(context.Background(), server.URL+"/claims-http.zip", checksum, "catalog:official:claims-http", false)
	if err != nil {
		t.Fatalf("failed to install plugin from url: %v", err)
	}
	if summary.ID != "claims-http" || summary.PackageSHA256 != checksum {
		t.Fatalf("unexpected plugin summary from url install: %#v", summary)
	}

	state, err := LoadState(filepath.Join(dir, "claims-http"))
	if err != nil {
		t.Fatalf("failed to load plugin state: %v", err)
	}
	if state == nil || state.Source != "catalog:official:claims-http" || state.PackageSHA256 != checksum {
		t.Fatalf("unexpected plugin state after url install: %#v", state)
	}
}

func TestRuntimeInstallURLRejectsDisallowedDownloadHost(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:              true,
		Directories:          []string{dir},
		AllowedDownloadHosts: []string{"downloads.example.com"},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(buildPluginArchive(t, map[string]string{
			"claims-http/mkauth-plugin.yaml": claimsHTTPManifest("https://actions.example.com/claims"),
		}))
	}))
	defer server.Close()

	if _, err := runtime.InstallURL(context.Background(), server.URL+"/claims-http.zip", "", "", false); err == nil {
		t.Fatalf("expected disallowed download host to be rejected")
	}
}

func TestRuntimeRejectsDisallowedHTTPActionHost(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:            true,
		Directories:        []string{dir},
		AllowedActionHosts: []string{"actions.example.com"},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	archive := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": claimsHTTPManifest("https://evil.example.com/claims"),
	})
	if _, err := runtime.InstallZip("claims-http.zip", archive, false); err == nil {
		t.Fatalf("expected disallowed http action host to be rejected")
	}
}

func TestRuntimeInstallsPluginFromCatalogEntry(t *testing.T) {
	dir := t.TempDir()
	archive := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": claimsHTTPManifest("https://actions.example.com/claims"),
	})
	checksum := sha256Hex(archive)

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/catalog.yaml":
			_, _ = w.Write([]byte("version: \"1\"\nplugins:\n  - id: \"claims-http\"\n    name: \"Claims HTTP Action\"\n    version: \"0.1.0\"\n    type: \"flow_action\"\n    download_url: \"" + serverURL + "/claims-http.zip\"\n    package_sha256: \"" + checksum + "\"\n"))
		case "/claims-http.zip":
			w.Header().Set("Content-Disposition", `attachment; filename="claims-http.zip"`)
			_, _ = w.Write(archive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:              true,
		Directories:          []string{dir},
		AllowPrivateNetworks: true,
		Catalogs: []config.PluginCatalogConfig{{
			ID:      "official",
			URL:     server.URL + "/catalog.yaml",
			Enabled: true,
		}},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	summary, err := runtime.InstallCatalogEntry(context.Background(), "official", "claims-http", false)
	if err != nil {
		t.Fatalf("failed to install plugin from catalog entry: %v", err)
	}
	if summary.ID != "claims-http" || summary.PackageSHA256 != checksum {
		t.Fatalf("unexpected plugin summary from catalog install: %#v", summary)
	}

	entries, err := runtime.ListCatalogEntries(context.Background())
	if err != nil {
		t.Fatalf("failed to list catalog entries after install: %v", err)
	}
	if len(entries) != 1 || !entries[0].Installed || entries[0].InstalledVersion != "0.1.0" || entries[0].UpdateAvailable {
		t.Fatalf("expected catalog entry to be annotated as installed without update, got %#v", entries)
	}
}

func claimsHTTPManifest(actionURL string) string {
	return "id: claims-http\n" +
		"name: Claims HTTP Action\n" +
		"version: 0.1.0\n" +
		"type: flow_action\n" +
		"permissions:\n" +
		"  - hook:before_token_issue\n" +
		"  - network:http_action\n" +
		"events:\n" +
		"  - before_token_issue\n" +
		"http_action:\n" +
		"  url: \"" + actionURL + "\"\n" +
		"  timeout_ms: 1000\n"
}

func buildPluginArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		fileWriter, err := writer.Create(name)
		if err != nil {
			t.Fatalf("failed to create archive entry %q: %v", name, err)
		}
		if _, err := fileWriter.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write archive entry %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close archive: %v", err)
	}
	return buffer.Bytes()
}

func signManifest(t *testing.T, privateKey ed25519.PrivateKey, manifest string) string {
	t.Helper()
	signature := ed25519.Sign(privateKey, []byte(manifest))
	return "key_id: test-signer\nalgorithm: ed25519\nsignature: " + base64.StdEncoding.EncodeToString(signature) + "\n"
}
