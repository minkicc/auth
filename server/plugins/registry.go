/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

type PluginType string

type PluginSource string

const (
	PluginTypeIdentityConnector PluginType = "identity_connector"
	PluginTypeFlowAction        PluginType = "flow_action"
	PluginTypeClaimMapper       PluginType = "claim_mapper"
	PluginTypeProvisioning      PluginType = "provisioning_connector"
	PluginTypeAuditSink         PluginType = "audit_sink"

	PluginSourceBuiltin PluginSource = "builtin"
	PluginSourceLocal   PluginSource = "local"
	PluginSourceHTTP    PluginSource = "http_action"
)

type Manifest struct {
	ID            string              `json:"id" yaml:"id"`
	Name          string              `json:"name" yaml:"name"`
	Version       string              `json:"version" yaml:"version"`
	Type          string              `json:"type" yaml:"type"`
	Entry         string              `json:"entry" yaml:"entry"`
	Description   string              `json:"description" yaml:"description"`
	Events        []string            `json:"events" yaml:"events"`
	Permissions   []string            `json:"permissions" yaml:"permissions"`
	ConfigSchema  []ConfigField       `json:"config_schema,omitempty" yaml:"config_schema,omitempty"`
	ClaimMappings []ClaimMapping      `json:"claim_mappings,omitempty" yaml:"claim_mappings,omitempty"`
	HTTPAction    *ManifestHTTPAction `json:"http_action,omitempty" yaml:"http_action,omitempty"`
	AuditSink     *ManifestAuditSink  `json:"audit_sink,omitempty" yaml:"audit_sink,omitempty"`
}

type ConfigField struct {
	Key         string   `json:"key" yaml:"key"`
	Label       string   `json:"label,omitempty" yaml:"label,omitempty"`
	Type        string   `json:"type,omitempty" yaml:"type,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool     `json:"required,omitempty" yaml:"required,omitempty"`
	Default     string   `json:"default,omitempty" yaml:"default,omitempty"`
	Options     []string `json:"options,omitempty" yaml:"options,omitempty"`
	Sensitive   bool     `json:"sensitive,omitempty" yaml:"sensitive,omitempty"`
}

type ManifestHTTPAction struct {
	URL       string `json:"url" yaml:"url"`
	Secret    string `json:"secret,omitempty" yaml:"secret,omitempty"`
	SecretEnv string `json:"secret_env,omitempty" yaml:"secret_env,omitempty"`
	TimeoutMS int    `json:"timeout_ms,omitempty" yaml:"timeout_ms,omitempty"`
	FailOpen  bool   `json:"fail_open,omitempty" yaml:"fail_open,omitempty"`
}

type ManifestAuditSink struct {
	URL           string   `json:"url" yaml:"url"`
	Secret        string   `json:"secret,omitempty" yaml:"secret,omitempty"`
	SecretEnv     string   `json:"secret_env,omitempty" yaml:"secret_env,omitempty"`
	TimeoutMS     int      `json:"timeout_ms,omitempty" yaml:"timeout_ms,omitempty"`
	FailOpen      bool     `json:"fail_open,omitempty" yaml:"fail_open,omitempty"`
	Actions       []string `json:"actions,omitempty" yaml:"actions,omitempty"`
	ResourceTypes []string `json:"resource_types,omitempty" yaml:"resource_types,omitempty"`
	SuccessOnly   bool     `json:"success_only,omitempty" yaml:"success_only,omitempty"`
	FailureOnly   bool     `json:"failure_only,omitempty" yaml:"failure_only,omitempty"`
}

type ClaimMapping struct {
	Claim         string   `json:"claim" yaml:"claim"`
	Value         string   `json:"value,omitempty" yaml:"value,omitempty"`
	ValueFrom     string   `json:"value_from,omitempty" yaml:"value_from,omitempty"`
	Clients       []string `json:"clients,omitempty" yaml:"clients,omitempty"`
	Organizations []string `json:"organizations,omitempty" yaml:"organizations,omitempty"`
}

type Summary struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Version           string         `json:"version,omitempty"`
	Type              string         `json:"type"`
	Source            PluginSource   `json:"source"`
	Entry             string         `json:"entry,omitempty"`
	Description       string         `json:"description,omitempty"`
	Events            []string       `json:"events,omitempty"`
	Permissions       []string       `json:"permissions,omitempty"`
	ConfigSchema      []ConfigField  `json:"config_schema,omitempty"`
	ClaimMappings     []ClaimMapping `json:"claim_mappings,omitempty"`
	ConfigConfigured  bool           `json:"config_configured,omitempty"`
	Enabled           bool           `json:"enabled"`
	SignatureVerified bool           `json:"signature_verified"`
	SignerKeyID       string         `json:"signer_key_id,omitempty"`
	PackageSHA256     string         `json:"package_sha256,omitempty"`
	Path              string         `json:"path,omitempty"`
}

var pluginIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,62}$`)

type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Summary
}

func NewRegistry(cfg config.PluginsConfig) (*Registry, error) {
	registry := &Registry{plugins: map[string]Summary{}}
	if !cfg.Enabled {
		return registry, nil
	}

	for _, action := range cfg.HTTPActions {
		id := strings.TrimSpace(action.ID)
		if id == "" {
			return nil, fmt.Errorf("http action plugin id is required")
		}
		name := strings.TrimSpace(action.Name)
		if name == "" {
			name = id
		}
		registry.Register(Summary{
			ID:          id,
			Name:        name,
			Type:        string(PluginTypeFlowAction),
			Source:      PluginSourceHTTP,
			Entry:       "http_action",
			Description: "Configured HTTP action plugin",
			Events:      normalizeEventList(action.Events),
			Permissions: configuredHTTPActionPermissions(action.Events),
			Enabled:     action.Enabled,
		})
	}

	enabledFilter := stringSet(cfg.EnabledPlugins)
	disabledFilter := stringSet(cfg.DisabledPlugins)
	for _, directory := range cfg.Directories {
		if err := registry.LoadDirectory(directory, cfg, enabledFilter, disabledFilter); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func (r *Registry) Register(summary Summary) {
	if r == nil || strings.TrimSpace(summary.ID) == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.plugins == nil {
		r.plugins = map[string]Summary{}
	}
	summary.ID = strings.TrimSpace(summary.ID)
	if strings.TrimSpace(summary.Name) == "" {
		summary.Name = summary.ID
	}
	summary.Type = strings.TrimSpace(summary.Type)
	if summary.Source == "" {
		summary.Source = PluginSourceBuiltin
	}
	if summary.Source == PluginSourceBuiltin {
		summary.SignatureVerified = true
	}
	r.plugins[summary.ID] = summary
}

func (r *Registry) LoadDirectory(directory string, cfg config.PluginsConfig, enabledFilter, disabledFilter map[string]struct{}) error {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read plugin directory %q: %w", directory, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		plugin, err := inspectLocalPluginDir(filepath.Join(directory, entry.Name()), cfg, enabledFilter, disabledFilter)
		if err != nil {
			return err
		}
		if plugin == nil {
			continue
		}
		r.Register(Summary{
			ID:                plugin.Manifest.ID,
			Name:              plugin.Manifest.Name,
			Version:           plugin.Manifest.Version,
			Type:              plugin.Manifest.Type,
			Source:            PluginSourceLocal,
			Entry:             plugin.Manifest.Entry,
			Description:       plugin.Manifest.Description,
			Events:            append([]string(nil), plugin.Manifest.Events...),
			Permissions:       append([]string(nil), plugin.Manifest.Permissions...),
			ConfigSchema:      append([]ConfigField(nil), plugin.Manifest.ConfigSchema...),
			ClaimMappings:     append([]ClaimMapping(nil), plugin.Manifest.ClaimMappings...),
			ConfigConfigured:  hasConfiguredPluginConfig(plugin.Manifest, plugin.State),
			Enabled:           plugin.Enabled,
			SignatureVerified: plugin.Verification.Verified,
			SignerKeyID:       plugin.Verification.KeyID,
			PackageSHA256:     plugin.PackageSHA256,
			Path:              plugin.Directory,
		})
	}
	return nil
}

func LoadManifest(path string) (Manifest, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read plugin manifest %q: %w", path, err)
	}
	return LoadManifestContent(content, path)
}

func LoadManifestContent(content []byte, path string) (Manifest, error) {
	var manifest Manifest
	if err := yaml.Unmarshal(content, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse plugin manifest %q: %w", path, err)
	}
	manifest.ID = strings.TrimSpace(manifest.ID)
	manifest.Name = strings.TrimSpace(manifest.Name)
	manifest.Version = strings.TrimSpace(manifest.Version)
	manifest.Type = strings.TrimSpace(manifest.Type)
	manifest.Entry = strings.TrimSpace(manifest.Entry)
	manifest.Description = strings.TrimSpace(manifest.Description)
	manifest.Events = normalizeEventList(manifest.Events)
	manifest.Permissions = normalizePermissionList(manifest.Permissions)
	manifest.ConfigSchema = normalizeConfigSchema(manifest.ConfigSchema)
	manifest.ClaimMappings = normalizeClaimMappings(manifest.ClaimMappings)
	if manifest.ID == "" {
		return Manifest{}, fmt.Errorf("plugin manifest %q missing id", path)
	}
	if !pluginIDPattern.MatchString(manifest.ID) {
		return Manifest{}, fmt.Errorf("plugin manifest %q has invalid id %q", path, manifest.ID)
	}
	if manifest.Name == "" {
		manifest.Name = manifest.ID
	}
	if manifest.Type == "" {
		return Manifest{}, fmt.Errorf("plugin manifest %q missing type", path)
	}
	if manifest.Type == string(PluginTypeClaimMapper) && len(manifest.Events) == 0 {
		manifest.Events = []string{string(iam.HookBeforeTokenIssue), string(iam.HookBeforeUserInfo)}
	}
	if manifest.Entry == "" && manifest.HTTPAction != nil {
		manifest.Entry = "http_action"
	}
	if manifest.Entry == "" && manifest.AuditSink != nil {
		manifest.Entry = "audit_sink"
	}
	if manifest.Entry == "" {
		manifest.Entry = "manifest"
	}
	if manifest.Entry == "http_action" && manifest.HTTPAction == nil {
		return Manifest{}, fmt.Errorf("plugin manifest %q missing http_action configuration", path)
	}
	if manifest.Type == string(PluginTypeAuditSink) && manifest.AuditSink == nil {
		return Manifest{}, fmt.Errorf("plugin manifest %q type %q requires audit_sink configuration", path, PluginTypeAuditSink)
	}
	if manifest.Entry == "audit_sink" && manifest.AuditSink == nil {
		return Manifest{}, fmt.Errorf("plugin manifest %q missing audit_sink configuration", path)
	}
	if manifest.AuditSink != nil {
		manifest.AuditSink.URL = strings.TrimSpace(manifest.AuditSink.URL)
		manifest.AuditSink.Secret = strings.TrimSpace(manifest.AuditSink.Secret)
		manifest.AuditSink.SecretEnv = strings.TrimSpace(manifest.AuditSink.SecretEnv)
		manifest.AuditSink.Actions = normalizeStringList(manifest.AuditSink.Actions, true)
		manifest.AuditSink.ResourceTypes = normalizeStringList(manifest.AuditSink.ResourceTypes, true)
		if manifest.AuditSink.SuccessOnly && manifest.AuditSink.FailureOnly {
			return Manifest{}, fmt.Errorf("plugin manifest %q audit_sink cannot set both success_only and failure_only", path)
		}
	}
	if !isSupportedPluginType(manifest.Type) {
		return Manifest{}, fmt.Errorf("plugin manifest %q has unsupported type %q", path, manifest.Type)
	}
	if err := validateConfigSchema(manifest.ConfigSchema, path); err != nil {
		return Manifest{}, err
	}
	if err := validateClaimMappings(manifest, path); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (r *Registry) List() []Summary {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.plugins) == 0 {
		return nil
	}
	items := make([]Summary, 0, len(r.plugins))
	for _, item := range r.plugins {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func PublicSummaries(items []Summary) []Summary {
	if len(items) == 0 {
		return []Summary{}
	}
	sanitized := make([]Summary, 0, len(items))
	for _, item := range items {
		item.Path = ""
		item.PackageSHA256 = ""
		item.SignerKeyID = ""
		sanitized = append(sanitized, item)
	}
	return sanitized
}

func (r *Registry) Get(id string) (Summary, bool) {
	if r == nil {
		return Summary{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.plugins[strings.TrimSpace(id)]
	return item, ok
}

func (r *Registry) Replace(items []Summary) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	replaced := make(map[string]Summary, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.ID) == "" {
			continue
		}
		replaced[strings.TrimSpace(item.ID)] = item
	}
	r.plugins = replaced
}

func findManifest(directory string) (string, bool) {
	for _, name := range []string{"mkauth-plugin.yaml", "plugin.yaml", "plugin.yml"} {
		path := filepath.Join(directory, name)
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func stringSet(items []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			set[item] = struct{}{}
		}
	}
	return set
}

func isPluginEnabled(id string, enabledFilter, disabledFilter map[string]struct{}) bool {
	if _, disabled := disabledFilter[id]; disabled {
		return false
	}
	if len(enabledFilter) == 0 {
		return true
	}
	_, enabled := enabledFilter[id]
	return enabled
}

func resolveEnabled(id string, state *State, enabledFilter, disabledFilter map[string]struct{}) bool {
	enabled := isPluginEnabled(id, enabledFilter, disabledFilter)
	if !enabled {
		return false
	}
	if state == nil || state.Enabled == nil {
		return true
	}
	return *state.Enabled
}

func isSupportedPluginType(kind string) bool {
	switch strings.TrimSpace(kind) {
	case string(PluginTypeIdentityConnector), string(PluginTypeFlowAction), string(PluginTypeClaimMapper), string(PluginTypeProvisioning), string(PluginTypeAuditSink):
		return true
	default:
		return false
	}
}
