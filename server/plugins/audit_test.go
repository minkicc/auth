package plugins

import (
	"path/filepath"
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestRuntimeRecordsPluginAudit(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:     true,
		Directories: []string{dir},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	actor := AuditActor{ID: "admin", IP: "127.0.0.1", UserAgent: "test-agent"}
	archive := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": claimsHTTPManifest("https://actions.example.com/claims"),
	})
	if _, err := runtime.InstallZipWithActor("claims-http.zip", archive, false, actor); err != nil {
		t.Fatalf("failed to install plugin: %v", err)
	}
	if _, err := runtime.SetEnabledWithActor("claims-http", false, actor); err != nil {
		t.Fatalf("failed to disable plugin: %v", err)
	}
	if err := runtime.UninstallWithActor("claims-http", actor); err != nil {
		t.Fatalf("failed to uninstall plugin: %v", err)
	}

	events, err := runtime.ListAudit(10)
	if err != nil {
		t.Fatalf("failed to list audit events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected three audit events, got %#v", events)
	}
	if events[0].Action != "uninstall" || events[1].Action != "disable" || events[2].Action != "install_upload" {
		t.Fatalf("expected newest audit event first, got %#v", events)
	}
	if events[2].Actor.ID != "admin" || !events[2].Success || events[2].PluginID != "claims-http" {
		t.Fatalf("unexpected install audit event: %#v", events[2])
	}
	if events[2].Details["filename"] != "claims-http.zip" || events[2].Details["package_sha256"] == "" {
		t.Fatalf("expected install audit details, got %#v", events[2].Details)
	}
}

func TestRuntimeRecordsFailedPluginAudit(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:     true,
		Directories: []string{dir},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	if _, err := runtime.InstallZipWithActor("broken.zip", []byte("not a zip"), false, AuditActor{ID: "admin"}); err == nil {
		t.Fatalf("expected broken archive install to fail")
	}

	events, err := runtime.ListAudit(1)
	if err != nil {
		t.Fatalf("failed to list audit events: %v", err)
	}
	if len(events) != 1 || events[0].Success || events[0].Error == "" {
		t.Fatalf("expected failed audit event, got %#v", events)
	}
	if _, err := LoadState(filepath.Join(dir, "claims-http")); err != nil {
		t.Fatalf("failed state lookup should remain safe: %v", err)
	}
}
