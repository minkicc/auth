package plugins

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestLoadCatalogEntries(t *testing.T) {
	baseURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`version: "1"
plugins:
  - id: "claims-http"
    name: "Claims HTTP Action"
    version: "0.1.0"
    type: "flow_action"
    description: "Installs an HTTP claims plugin."
    permissions:
      - "hook:before_token_issue"
      - "network:http_action"
    download_url: "%s/plugins/claims-http.zip"
    homepage: "https://example.com/plugins/claims-http"
    package_sha256: "abc123"
    signature_required: true
`, baseURL)))
	}))
	defer server.Close()
	baseURL = server.URL

	entries, err := LoadCatalogEntries(context.Background(), config.PluginsConfig{
		Enabled:              true,
		AllowPrivateNetworks: true,
		Catalogs: []config.PluginCatalogConfig{{
			ID:      "official",
			Name:    "Official Catalog",
			URL:     server.URL + "/catalog.yaml",
			Enabled: true,
		}},
	})
	if err != nil {
		t.Fatalf("failed to load catalog entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one catalog entry, got %#v", entries)
	}
	entry := entries[0]
	if entry.CatalogID != "official" || entry.ID != "claims-http" || entry.DownloadURL == "" || !entry.SignatureRequired {
		t.Fatalf("unexpected catalog entry: %#v", entry)
	}
	if len(entry.Permissions) != 2 {
		t.Fatalf("expected catalog permissions to be loaded, got %#v", entry.Permissions)
	}
}

func TestLoadCatalogEntriesRejectsDisallowedCatalogHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("version: \"1\"\nplugins: []\n"))
	}))
	defer server.Close()

	if _, err := LoadCatalogEntries(context.Background(), config.PluginsConfig{
		Enabled:             true,
		AllowedCatalogHosts: []string{"catalogs.example.com"},
		Catalogs: []config.PluginCatalogConfig{{
			ID:      "official",
			URL:     server.URL + "/catalog.yaml",
			Enabled: true,
		}},
	}); err == nil {
		t.Fatalf("expected disallowed catalog host to be rejected")
	}
}

func TestLoadCatalogEntriesRejectsDownloadHostOutsideCatalogTrust(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`version: "1"
plugins:
  - id: "claims-http"
    name: "Claims HTTP Action"
    type: "flow_action"
    download_url: "https://downloads.example.com/plugins/claims-http.zip"
`))
	}))
	defer server.Close()

	if _, err := LoadCatalogEntries(context.Background(), config.PluginsConfig{
		Enabled:              true,
		AllowPrivateNetworks: true,
		Catalogs: []config.PluginCatalogConfig{{
			ID:      "official",
			URL:     server.URL + "/catalog.yaml",
			Enabled: true,
		}},
	}); err == nil {
		t.Fatalf("expected disallowed catalog download host to be rejected")
	}
}

func TestLoadCatalogEntriesAllowsConfiguredDownloadHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`version: "1"
plugins:
  - id: "claims-http"
    name: "Claims HTTP Action"
    type: "flow_action"
    download_url: "https://downloads.example.com/plugins/claims-http.zip"
`))
	}))
	defer server.Close()

	entries, err := LoadCatalogEntries(context.Background(), config.PluginsConfig{
		Enabled:              true,
		AllowPrivateNetworks: true,
		AllowedDownloadHosts: []string{"downloads.example.com"},
		Catalogs: []config.PluginCatalogConfig{{
			ID:      "official",
			URL:     server.URL + "/catalog.yaml",
			Enabled: true,
		}},
	})
	if err != nil {
		t.Fatalf("expected configured download host to be allowed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one catalog entry, got %#v", entries)
	}
}

func TestAnnotateCatalogEntriesMarksInstalledAndUpdateAvailable(t *testing.T) {
	registry, err := NewRegistry(config.PluginsConfig{})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	registry.Register(Summary{
		ID:            "claims-http",
		Name:          "Claims HTTP Action",
		Version:       "0.1.0",
		Source:        PluginSourceLocal,
		PackageSHA256: "old-sha",
		Enabled:       true,
	})

	entries := annotateCatalogEntries([]CatalogEntry{{
		CatalogID:     "official",
		ID:            "claims-http",
		Name:          "Claims HTTP Action",
		Version:       "0.2.0",
		PackageSHA256: "new-sha",
	}}, registry)

	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %#v", entries)
	}
	entry := entries[0]
	if !entry.Installed || entry.InstalledVersion != "0.1.0" || entry.InstalledSource != PluginSourceLocal {
		t.Fatalf("expected installed metadata, got %#v", entry)
	}
	if !entry.UpdateAvailable || entry.UpdateReason != "newer_version" {
		t.Fatalf("expected newer version update metadata, got %#v", entry)
	}
}

func TestCatalogUpdateStatusUsesChecksumForSameVersion(t *testing.T) {
	available, reason := catalogUpdateStatus(CatalogEntry{
		Version:       "1.0.0",
		PackageSHA256: "new-sha",
	}, Summary{
		Version:       "1.0.0",
		PackageSHA256: "old-sha",
	})
	if !available || reason != "package_changed" {
		t.Fatalf("expected package checksum update, got available=%t reason=%q", available, reason)
	}
}
