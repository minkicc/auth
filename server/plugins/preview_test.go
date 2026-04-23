package plugins

import (
	"strings"
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestRuntimePreviewZipReportsReplaceImpact(t *testing.T) {
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
		t.Fatalf("failed to configure plugin: %v", err)
	}
	if _, err := runtime.SetEnabled("claims-http", false); err != nil {
		t.Fatalf("failed to disable plugin: %v", err)
	}

	archiveV2 := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": configurableClaimsHTTPManifestV("0.2.0", "https://actions.example.com/claims"),
	})
	preview, err := runtime.PreviewZip("claims-http-v2.zip", archiveV2, false)
	if err != nil {
		t.Fatalf("failed to preview plugin: %v", err)
	}
	if !preview.Exists || !preview.RequiresReplace || !preview.EffectiveReplace || !preview.WillBackup {
		t.Fatalf("expected replace metadata, got %#v", preview)
	}
	if preview.Existing == nil || preview.Existing.Version != "0.1.0" || preview.Version != "0.2.0" {
		t.Fatalf("expected existing and next version metadata, got %#v", preview)
	}
	if preview.EnabledAfterInstall {
		t.Fatalf("expected disabled state to be preserved in preview, got %#v", preview)
	}
	if !sameStringSet(preview.PreservedConfigKeys, []string{"secret", "timeout_ms", "url"}) {
		t.Fatalf("expected preserved config keys, got %#v", preview.PreservedConfigKeys)
	}
	if len(preview.Warnings) == 0 {
		t.Fatalf("expected replacement warning, got %#v", preview)
	}

	current, ok := runtime.Registry().Get("claims-http")
	if !ok || current.Version != "0.1.0" {
		t.Fatalf("preview should not install or replace plugin, got %#v", current)
	}
}

func TestRuntimePreviewRejectsBuiltinIDConflict(t *testing.T) {
	dir := t.TempDir()
	runtime, err := NewRuntime(config.PluginsConfig{
		Enabled:              true,
		Directories:          []string{dir},
		AllowPrivateNetworks: true,
	})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	if err := runtime.RegisterBuiltin(Summary{
		ID:      "claims-http",
		Name:    "Builtin Claims",
		Type:    string(PluginTypeFlowAction),
		Source:  PluginSourceBuiltin,
		Enabled: true,
	}); err != nil {
		t.Fatalf("failed to register builtin: %v", err)
	}
	archive := buildPluginArchive(t, map[string]string{
		"claims-http/mkauth-plugin.yaml": configurableClaimsHTTPManifest("https://actions.example.com/claims"),
	})
	if _, err := runtime.PreviewZip("claims-http.zip", archive, true); err == nil {
		t.Fatalf("expected builtin ID conflict to be rejected")
	}
	if _, err := runtime.InstallZip("claims-http.zip", archive, true); err == nil {
		t.Fatalf("expected install over builtin ID conflict to be rejected")
	}
}

func sameStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, item := range got {
		seen[item]++
	}
	for _, item := range want {
		if seen[item] == 0 {
			return false
		}
		seen[item]--
	}
	return true
}

func configurableClaimsHTTPManifestV(version, actionURL string) string {
	return strings.Replace(configurableClaimsHTTPManifest(actionURL), "version: 0.1.0", "version: "+version, 1)
}
