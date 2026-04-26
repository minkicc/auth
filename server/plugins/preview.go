package plugins

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type InstallPreview struct {
	ID                    string         `json:"id"`
	Name                  string         `json:"name"`
	Version               string         `json:"version,omitempty"`
	Type                  string         `json:"type"`
	Entry                 string         `json:"entry,omitempty"`
	Description           string         `json:"description,omitempty"`
	Events                []string       `json:"events,omitempty"`
	Permissions           []string       `json:"permissions,omitempty"`
	ConfigSchema          []ConfigField  `json:"config_schema,omitempty"`
	ClaimMappings         []ClaimMapping `json:"claim_mappings,omitempty"`
	PackageSHA256         string         `json:"package_sha256"`
	SignatureVerified     bool           `json:"signature_verified"`
	SignerKeyID           string         `json:"signer_key_id,omitempty"`
	Exists                bool           `json:"exists"`
	Existing              *Summary       `json:"existing,omitempty"`
	RequiresReplace       bool           `json:"requires_replace,omitempty"`
	WillBackup            bool           `json:"will_backup,omitempty"`
	EnabledAfterInstall   bool           `json:"enabled_after_install"`
	PreservedConfigKeys   []string       `json:"preserved_config_keys,omitempty"`
	DroppedConfigKeys     []string       `json:"dropped_config_keys,omitempty"`
	Warnings              []string       `json:"warnings,omitempty"`
	RequestedReplace      bool           `json:"requested_replace"`
	EffectiveReplace      bool           `json:"effective_replace"`
	ExistingPackageSHA256 string         `json:"existing_package_sha256,omitempty"`
}

func (r *Runtime) PreviewZip(filename string, content []byte, replace bool) (InstallPreview, error) {
	if r == nil {
		return InstallPreview{}, fmt.Errorf("plugin runtime is not initialized")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.previewArchiveLocked(filename, content, replace)
}

func (r *Runtime) previewArchiveLocked(_ string, content []byte, replace bool) (InstallPreview, error) {
	if !r.cfg.Enabled {
		return InstallPreview{}, fmt.Errorf("plugin runtime is disabled")
	}
	manifest, rootPrefix, archive, err := parsePluginArchive(content)
	if err != nil {
		return InstallPreview{}, err
	}
	if err := ValidateManifestPermissions(manifest, r.cfg); err != nil {
		return InstallPreview{}, err
	}

	installDir, targetDir, existing, err := r.installTargetLocked(manifest.ID)
	if err != nil {
		return InstallPreview{}, err
	}
	tempDir, err := os.MkdirTemp(installDir, manifest.ID+".preview-*")
	if err != nil {
		return InstallPreview{}, fmt.Errorf("create temporary preview directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	if err := extractPluginArchive(archive, rootPrefix, tempDir); err != nil {
		return InstallPreview{}, err
	}
	plugin, err := inspectLocalPluginDir(tempDir, r.cfg, nil, nil)
	if err != nil {
		return InstallPreview{}, err
	}
	if plugin == nil {
		return InstallPreview{}, fmt.Errorf("plugin archive is missing a manifest file")
	}

	preview := InstallPreview{
		ID:                  manifest.ID,
		Name:                manifest.Name,
		Version:             manifest.Version,
		Type:                manifest.Type,
		Entry:               manifest.Entry,
		Description:         manifest.Description,
		Events:              append([]string(nil), manifest.Events...),
		Permissions:         append([]string(nil), manifest.Permissions...),
		ConfigSchema:        append([]ConfigField(nil), manifest.ConfigSchema...),
		ClaimMappings:       append([]ClaimMapping(nil), manifest.ClaimMappings...),
		PackageSHA256:       sha256Hex(content),
		SignatureVerified:   plugin.Verification.Verified,
		SignerKeyID:         plugin.Verification.KeyID,
		EnabledAfterInstall: true,
		RequestedReplace:    replace,
		EffectiveReplace:    replace,
	}

	if existing != nil {
		preview.Exists = true
		preview.Existing = existing
		preview.RequiresReplace = true
		preview.EffectiveReplace = true
		preview.WillBackup = preview.EffectiveReplace
		preview.EnabledAfterInstall = existing.Enabled
		preview.ExistingPackageSHA256 = existing.PackageSHA256
		preview.PreservedConfigKeys, preview.DroppedConfigKeys = previewConfigKeyChanges(manifest, existing.Path)
	} else if _, err := os.Stat(targetDir); err == nil {
		preview.Exists = true
		preview.RequiresReplace = true
		preview.EffectiveReplace = true
		preview.WillBackup = preview.EffectiveReplace
		preview.Warnings = append(preview.Warnings, "A plugin directory with the same ID exists but is not currently loaded.")
	} else if err != nil && !os.IsNotExist(err) {
		return InstallPreview{}, fmt.Errorf("inspect plugin %s: %w", manifest.ID, err)
	}
	if preview.Exists && !replace {
		preview.Warnings = append(preview.Warnings, "Installing this package requires replace=true because the plugin ID already exists.")
	}
	if !preview.SignatureVerified && !r.cfg.RequireSignature {
		preview.Warnings = append(preview.Warnings, "Plugin package is unsigned; enable plugins.require_signature to require trusted signatures.")
	}
	sort.Strings(preview.Warnings)
	return preview, nil
}

func previewConfigKeyChanges(manifest Manifest, existingPath string) ([]string, []string) {
	if strings.TrimSpace(existingPath) == "" {
		return nil, nil
	}
	state, err := LoadState(existingPath)
	if err != nil || state == nil || len(state.Config) == 0 {
		return nil, nil
	}
	schema := configSchemaMap(manifest.ConfigSchema)
	preserved := make([]string, 0, len(state.Config))
	dropped := make([]string, 0, len(state.Config))
	for key := range state.Config {
		key = strings.TrimSpace(strings.ToLower(key))
		if key == "" {
			continue
		}
		if _, ok := schema[key]; ok {
			preserved = append(preserved, key)
		} else {
			dropped = append(dropped, key)
		}
	}
	sort.Strings(preserved)
	sort.Strings(dropped)
	return preserved, dropped
}
