package plugins

import (
	"os"
	"path/filepath"
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestRegistryLoadsLocalManifestPlugins(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "claims")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatalf("failed to create plugin dir: %v", err)
	}
	manifest := []byte(`id: claims-http
name: Claims HTTP Action
version: 0.1.0
type: flow_action
entry: http_action
description: Adds claims through HTTP.
permissions:
  - hook:before_token_issue
  - network:http_action
events:
  - before_token_issue
http_action:
  url: "https://actions.example.com/claims"
`)
	if err := os.WriteFile(filepath.Join(pluginDir, "mkauth-plugin.yaml"), manifest, 0o644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	registry, err := NewRegistry(config.PluginsConfig{Enabled: true, Directories: []string{dir}})
	if err != nil {
		t.Fatalf("failed to load registry: %v", err)
	}
	plugins := registry.List()
	if len(plugins) != 1 {
		t.Fatalf("expected one plugin, got %#v", plugins)
	}
	if plugins[0].ID != "claims-http" || plugins[0].Source != PluginSourceLocal || plugins[0].Type != "flow_action" {
		t.Fatalf("unexpected plugin summary: %#v", plugins[0])
	}
	if len(plugins[0].Permissions) != 2 {
		t.Fatalf("expected plugin permissions to be loaded, got %#v", plugins[0].Permissions)
	}
}

func TestRegistryHonorsEnabledAndDisabledFilters(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"first", "second"} {
		pluginDir := filepath.Join(dir, id)
		if err := os.MkdirAll(pluginDir, 0o755); err != nil {
			t.Fatalf("failed to create plugin dir: %v", err)
		}
		manifest := []byte("id: " + id + "\nname: " + id + "\ntype: flow_action\n")
		if err := os.WriteFile(filepath.Join(pluginDir, "plugin.yaml"), manifest, 0o644); err != nil {
			t.Fatalf("failed to write manifest: %v", err)
		}
	}

	registry, err := NewRegistry(config.PluginsConfig{
		Enabled:         true,
		Directories:     []string{dir},
		EnabledPlugins:  []string{"first", "second"},
		DisabledPlugins: []string{"second"},
	})
	if err != nil {
		t.Fatalf("failed to load registry: %v", err)
	}
	plugins := registry.List()
	if len(plugins) != 2 {
		t.Fatalf("expected two plugins, got %#v", plugins)
	}
	if plugins[0].ID != "first" || !plugins[0].Enabled {
		t.Fatalf("expected first plugin enabled, got %#v", plugins[0])
	}
	if plugins[1].ID != "second" || plugins[1].Enabled {
		t.Fatalf("expected second plugin disabled, got %#v", plugins[1])
	}
}

func TestRegistryIncludesConfiguredHTTPActions(t *testing.T) {
	registry, err := NewRegistry(config.PluginsConfig{
		Enabled: true,
		HTTPActions: []config.HTTPActionConfig{{
			ID:      "risk-check",
			Enabled: true,
			Events:  []string{"post_authenticate"},
			URL:     "https://actions.example.com/risk",
		}},
	})
	if err != nil {
		t.Fatalf("failed to load registry: %v", err)
	}
	plugins := registry.List()
	if len(plugins) != 1 || plugins[0].ID != "risk-check" || plugins[0].Source != PluginSourceHTTP {
		t.Fatalf("unexpected http action plugin: %#v", plugins)
	}
	if len(plugins[0].Permissions) != 2 {
		t.Fatalf("expected configured http action permissions, got %#v", plugins[0].Permissions)
	}
}
