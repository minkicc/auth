package plugins

import (
	"strings"
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestRuntimeCreatesBackupAndRestoresPlugin(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:     true,
		Directories: []string{dir},
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}

	v1 := claimsHTTPManifestWithVersion("0.1.0")
	v2 := claimsHTTPManifestWithVersion("0.2.0")
	if _, err := runtime.InstallZip("claims-http-v1.zip", buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": v1,
	}), false); err != nil {
		t.Fatalf("failed to install v1: %v", err)
	}
	if _, err := runtime.InstallZip("claims-http-v2.zip", buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": v2,
	}), true); err != nil {
		t.Fatalf("failed to replace with v2: %v", err)
	}

	backups, err := runtime.ListBackups("claims-http", 10)
	if err != nil {
		t.Fatalf("failed to list backups: %v", err)
	}
	if len(backups) != 1 || backups[0].Reason != "replace" || backups[0].PluginID != "claims-http" {
		t.Fatalf("unexpected backups after replace: %#v", backups)
	}

	restored, err := runtime.RestoreBackupWithActor(backups[0].ID, AuditActor{ID: "admin"})
	if err != nil {
		t.Fatalf("failed to restore backup: %v", err)
	}
	if restored.Version != "0.1.0" {
		t.Fatalf("expected restored v1 plugin, got %#v", restored)
	}

	backups, err = runtime.ListBackups("claims-http", 10)
	if err != nil {
		t.Fatalf("failed to list backups after restore: %v", err)
	}
	if len(backups) != 2 {
		t.Fatalf("expected restore to back up current plugin first, got %#v", backups)
	}
}

func claimsHTTPManifestWithVersion(version string) string {
	return strings.Replace(claimsHTTPManifest("https://actions.example.com/claims"), "version: 0.1.0", "version: "+version, 1)
}
