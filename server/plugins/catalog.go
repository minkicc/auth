package plugins

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"minki.cc/mkauth/server/config"
)

const (
	maxPluginCatalogSize = 1 << 20
	pluginCatalogTimeout = 15 * time.Second
)

type CatalogEntry struct {
	CatalogID         string   `json:"catalog_id"`
	CatalogName       string   `json:"catalog_name,omitempty"`
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Version           string   `json:"version,omitempty"`
	Type              string   `json:"type"`
	Description       string   `json:"description,omitempty"`
	Permissions       []string `json:"permissions,omitempty"`
	DownloadURL       string   `json:"download_url"`
	Homepage          string   `json:"homepage,omitempty"`
	PackageSHA256     string   `json:"package_sha256,omitempty"`
	SignatureRequired bool     `json:"signature_required"`
}

type catalogDocument struct {
	Version string             `json:"version" yaml:"version"`
	Plugins []catalogEntryYAML `json:"plugins" yaml:"plugins"`
}

type catalogEntryYAML struct {
	ID                string   `json:"id" yaml:"id"`
	Name              string   `json:"name" yaml:"name"`
	Version           string   `json:"version" yaml:"version"`
	Type              string   `json:"type" yaml:"type"`
	Description       string   `json:"description" yaml:"description"`
	Permissions       []string `json:"permissions" yaml:"permissions"`
	DownloadURL       string   `json:"download_url" yaml:"download_url"`
	Homepage          string   `json:"homepage" yaml:"homepage"`
	PackageSHA256     string   `json:"package_sha256" yaml:"package_sha256"`
	SignatureRequired bool     `json:"signature_required" yaml:"signature_required"`
}

func LoadCatalogEntries(ctx context.Context, cfg config.PluginsConfig) ([]CatalogEntry, error) {
	if !cfg.Enabled || len(cfg.Catalogs) == 0 {
		return nil, nil
	}

	entries := make([]CatalogEntry, 0)
	for _, catalog := range cfg.Catalogs {
		if !catalog.Enabled {
			continue
		}
		items, err := loadCatalog(ctx, cfg, catalog)
		if err != nil {
			return nil, err
		}
		entries = append(entries, items...)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CatalogID == entries[j].CatalogID {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].CatalogID < entries[j].CatalogID
	})
	return entries, nil
}

func loadCatalog(ctx context.Context, pluginsCfg config.PluginsConfig, cfg config.PluginCatalogConfig) ([]CatalogEntry, error) {
	catalogURL, err := validateRemoteURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("plugin catalog %q has invalid url: %w", cfg.ID, err)
	}
	if err := requireHostAllowed("plugin catalog", catalogURL, pluginsCfg.AllowedCatalogHosts, len(pluginsCfg.AllowedCatalogHosts) == 0); err != nil {
		return nil, fmt.Errorf("plugin catalog %q: %w", strings.TrimSpace(cfg.ID), err)
	}
	catalogID := strings.TrimSpace(cfg.ID)
	if catalogID == "" {
		catalogID = catalogURL.Host
	}
	catalogName := strings.TrimSpace(cfg.Name)
	if catalogName == "" {
		catalogName = catalogID
	}
	client := newRestrictedHTTPClient(pluginCatalogTimeout, allowlistForRequest(catalogURL.Host, pluginsCfg.AllowedCatalogHosts), pluginsCfg.AllowPrivateNetworks)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create plugin catalog request for %q: %w", catalogID, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch plugin catalog %q: %w", catalogID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("plugin catalog %q returned status %d", catalogID, resp.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, maxPluginCatalogSize+1))
	if err != nil {
		return nil, fmt.Errorf("read plugin catalog %q: %w", catalogID, err)
	}
	if len(content) > maxPluginCatalogSize {
		return nil, fmt.Errorf("plugin catalog %q exceeds the size limit", catalogID)
	}

	var document catalogDocument
	if err := yaml.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("parse plugin catalog %q: %w", catalogID, err)
	}

	entries := make([]CatalogEntry, 0, len(document.Plugins))
	for _, item := range document.Plugins {
		id := strings.TrimSpace(item.ID)
		if !pluginIDPattern.MatchString(id) {
			return nil, fmt.Errorf("plugin catalog %q contains invalid plugin id %q", catalogID, item.ID)
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = id
		}
		kind := strings.TrimSpace(item.Type)
		if !isSupportedPluginType(kind) {
			return nil, fmt.Errorf("plugin catalog %q has unsupported type %q for plugin %q", catalogID, item.Type, id)
		}
		permissions := normalizePermissionList(item.Permissions)
		if err := validateCatalogPermissions(id, permissions, pluginsCfg); err != nil {
			return nil, fmt.Errorf("plugin catalog %q: %w", catalogID, err)
		}
		downloadURL, err := validateRemoteURL(item.DownloadURL)
		if err != nil {
			return nil, fmt.Errorf("plugin catalog %q has invalid download_url for plugin %q: %w", catalogID, id, err)
		}
		if err := requireHostAllowed(
			fmt.Sprintf("plugin download source %q in catalog %q", id, catalogID),
			downloadURL,
			allowlistForRequest(catalogURL.Host, pluginsCfg.AllowedDownloadHosts),
			false,
		); err != nil {
			return nil, err
		}
		entries = append(entries, CatalogEntry{
			CatalogID:         catalogID,
			CatalogName:       catalogName,
			ID:                id,
			Name:              name,
			Version:           strings.TrimSpace(item.Version),
			Type:              kind,
			Description:       strings.TrimSpace(item.Description),
			Permissions:       permissions,
			DownloadURL:       downloadURL.String(),
			Homepage:          strings.TrimSpace(item.Homepage),
			PackageSHA256:     strings.TrimSpace(strings.ToLower(item.PackageSHA256)),
			SignatureRequired: item.SignatureRequired,
		})
	}
	return entries, nil
}

func validateRemoteURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("url is required")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, err
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("userinfo is not allowed")
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	return parsed, nil
}
