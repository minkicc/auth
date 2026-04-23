package plugins

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

const (
	maxPluginPackageSize     = 20 << 20
	maxPluginArchiveFiles    = 128
	maxPluginArchiveFileSize = 5 << 20
)

type Runtime struct {
	cfg      config.PluginsConfig
	mu       sync.Mutex
	registry *Registry
	hooks    *iam.HookRegistry
	builtins map[string]Summary
}

type installResult struct {
	Summary Summary
	Backup  *BackupSummary
}

func NewRuntime(cfg config.PluginsConfig) (*Runtime, error) {
	cfg = normalizeConfig(cfg)
	registry, err := NewRegistry(config.PluginsConfig{})
	if err != nil {
		return nil, err
	}
	hooks, err := iam.NewHookRegistry()
	if err != nil {
		return nil, err
	}
	runtime := &Runtime{
		cfg:      cfg,
		registry: registry,
		hooks:    hooks,
		builtins: map[string]Summary{},
	}
	if err := runtime.reloadLocked(); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *Runtime) Registry() *Registry {
	if r == nil {
		return nil
	}
	return r.registry
}

func (r *Runtime) Hooks() *iam.HookRegistry {
	if r == nil {
		return nil
	}
	return r.hooks
}

func (r *Runtime) List() []Summary {
	if r == nil || r.registry == nil {
		return nil
	}
	return r.registry.List()
}

func (r *Runtime) RegisterBuiltin(summary Summary) error {
	if r == nil || strings.TrimSpace(summary.ID) == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if summary.Source == "" {
		summary.Source = PluginSourceBuiltin
	}
	summary.Enabled = true
	r.builtins[summary.ID] = summary
	return r.reloadLocked()
}

func (r *Runtime) Reload() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked()
}

func (r *Runtime) InstallZip(filename string, content []byte, replace bool) (Summary, error) {
	return r.InstallZipWithActor(filename, content, replace, AuditActor{})
}

func (r *Runtime) InstallZipWithActor(filename string, content []byte, replace bool, actor AuditActor) (summary Summary, err error) {
	if r == nil {
		return Summary{}, fmt.Errorf("plugin runtime is not initialized")
	}
	source := "upload:" + strings.TrimSpace(filename)
	action := "install_upload"
	if replace {
		action = "replace_upload"
	}
	manifest, _, _, parseErr := parsePluginArchive(content)

	r.mu.Lock()
	defer r.mu.Unlock()
	previousDetails := map[string]string(nil)
	if replace && parseErr == nil {
		if previous, ok := r.registry.Get(manifest.ID); ok {
			previousDetails = auditPreviousSummaryDetails(previous)
		}
	}
	var result installResult
	defer func() {
		pluginID, pluginName, version := summary.ID, summary.Name, summary.Version
		if pluginID == "" && parseErr == nil {
			pluginID = manifest.ID
			pluginName = manifest.Name
			version = manifest.Version
		}
		r.appendAuditLocked(AuditEvent{
			Action:     action,
			PluginID:   pluginID,
			PluginName: pluginName,
			Version:    version,
			Source:     source,
			Actor:      actor,
			Success:    err == nil,
			Error:      auditError(err),
			Details: mergeAuditDetails(auditSummaryDetails(summary), previousDetails, auditBackupDetails(result.Backup), map[string]string{
				"filename": strings.TrimSpace(filename),
				"replace":  fmt.Sprintf("%t", replace),
			}),
		})
	}()
	result, err = r.installArchiveLocked(filename, content, replace, source)
	summary = result.Summary
	return summary, err
}

func (r *Runtime) installArchiveLocked(filename string, content []byte, replace bool, source string) (installResult, error) {
	if !r.cfg.Enabled {
		return installResult{}, fmt.Errorf("plugin runtime is disabled")
	}

	manifest, rootPrefix, archive, err := parsePluginArchive(content)
	if err != nil {
		return installResult{}, err
	}
	if err := ValidateManifestPermissions(manifest, r.cfg); err != nil {
		return installResult{}, err
	}

	installDir, err := r.primaryDirectory()
	if err != nil {
		return installResult{}, err
	}
	targetDir := filepath.Join(installDir, manifest.ID)
	if !replace {
		if _, err := os.Stat(targetDir); err == nil {
			return installResult{}, fmt.Errorf("plugin %s is already installed", manifest.ID)
		} else if !os.IsNotExist(err) {
			return installResult{}, fmt.Errorf("inspect plugin %s: %w", manifest.ID, err)
		}
	}

	tempDir, err := os.MkdirTemp(installDir, manifest.ID+".tmp-*")
	if err != nil {
		return installResult{}, fmt.Errorf("create temporary plugin directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	if err := extractPluginArchive(archive, rootPrefix, tempDir); err != nil {
		return installResult{}, err
	}
	if _, err := inspectLocalPluginDir(tempDir, r.cfg, nil, nil); err != nil {
		return installResult{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	state := State{
		Enabled:       boolPtr(true),
		Source:        strings.TrimSpace(source),
		PackageSHA256: sha256Hex(content),
		InstalledAt:   now,
		UpdatedAt:     now,
	}
	if replace {
		if previous, err := LoadState(targetDir); err == nil && previous != nil {
			if previous.InstalledAt != "" {
				state.InstalledAt = previous.InstalledAt
			}
			if previous.Enabled != nil {
				enabled := *previous.Enabled
				state.Enabled = &enabled
			}
			state.Config = filterPluginConfig(manifest, previous.Config)
		}
	}
	if err := SaveState(tempDir, state); err != nil {
		return installResult{}, err
	}

	var backup *BackupSummary
	if replace {
		if _, err := os.Stat(targetDir); err == nil {
			previous := Summary{ID: manifest.ID, Path: targetDir}
			if registrySummary, ok := r.registry.Get(manifest.ID); ok {
				previous = registrySummary
			}
			backup, err = r.createBackupLocked(previous, "replace")
			if err != nil {
				return installResult{}, err
			}
			if err := os.RemoveAll(targetDir); err != nil {
				return installResult{}, fmt.Errorf("remove existing plugin %s: %w", manifest.ID, err)
			}
		} else if err != nil && !os.IsNotExist(err) {
			return installResult{}, fmt.Errorf("inspect existing plugin %s: %w", manifest.ID, err)
		}
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return installResult{}, fmt.Errorf("create plugins directory %q: %w", installDir, err)
	}
	if err := os.Rename(tempDir, targetDir); err != nil {
		return installResult{}, fmt.Errorf("activate plugin %s: %w", manifest.ID, err)
	}
	if err := r.reloadLocked(); err != nil {
		return installResult{}, err
	}
	summary, ok := r.registry.Get(manifest.ID)
	if !ok {
		return installResult{}, fmt.Errorf("plugin %s was installed but not loaded", manifest.ID)
	}
	return installResult{Summary: summary, Backup: backup}, nil
}

func (r *Runtime) SetEnabled(id string, enabled bool) (Summary, error) {
	return r.SetEnabledWithActor(id, enabled, AuditActor{})
}

func (r *Runtime) SetEnabledWithActor(id string, enabled bool, actor AuditActor) (summary Summary, err error) {
	if r == nil {
		return Summary{}, fmt.Errorf("plugin runtime is not initialized")
	}
	action := "disable"
	if enabled {
		action = "enable"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func() {
		r.appendAuditLocked(AuditEvent{
			Action:     action,
			PluginID:   strings.TrimSpace(id),
			PluginName: summary.Name,
			Version:    summary.Version,
			Actor:      actor,
			Success:    err == nil,
			Error:      auditError(err),
			Details: mergeAuditDetails(auditSummaryDetails(summary), map[string]string{
				"enabled": fmt.Sprintf("%t", enabled),
			}),
		})
	}()

	summary, ok := r.registry.Get(id)
	if !ok {
		return Summary{}, fmt.Errorf("plugin %s was not found", id)
	}
	if summary.Source != PluginSourceLocal || summary.Path == "" {
		return Summary{}, fmt.Errorf("plugin %s is not a managed local plugin", id)
	}
	state, err := LoadState(summary.Path)
	if err != nil {
		return Summary{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if state == nil {
		state = &State{InstalledAt: now}
	}
	state.Enabled = boolPtr(enabled)
	state.UpdatedAt = now
	if err := SaveState(summary.Path, *state); err != nil {
		return Summary{}, err
	}
	if err := r.reloadLocked(); err != nil {
		return Summary{}, err
	}
	updated, ok := r.registry.Get(id)
	if !ok {
		return Summary{}, fmt.Errorf("plugin %s was not found after reload", id)
	}
	summary = updated
	return updated, nil
}

func (r *Runtime) Uninstall(id string) error {
	return r.UninstallWithActor(id, AuditActor{})
}

func (r *Runtime) UninstallWithActor(id string, actor AuditActor) (err error) {
	if r == nil {
		return fmt.Errorf("plugin runtime is not initialized")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var summary Summary
	var backup *BackupSummary
	defer func() {
		r.appendAuditLocked(AuditEvent{
			Action:     "uninstall",
			PluginID:   strings.TrimSpace(id),
			PluginName: summary.Name,
			Version:    summary.Version,
			Actor:      actor,
			Success:    err == nil,
			Error:      auditError(err),
			Details:    mergeAuditDetails(auditSummaryDetails(summary), auditBackupDetails(backup)),
		})
	}()

	var ok bool
	summary, ok = r.registry.Get(id)
	if !ok {
		return fmt.Errorf("plugin %s was not found", id)
	}
	if summary.Source != PluginSourceLocal || summary.Path == "" {
		return fmt.Errorf("plugin %s is not a managed local plugin", id)
	}
	if !r.isManagedPath(summary.Path) {
		return fmt.Errorf("plugin %s is outside managed plugin directories", id)
	}
	backup, err = r.createBackupLocked(summary, "uninstall")
	if err != nil {
		return err
	}
	if err := os.RemoveAll(summary.Path); err != nil {
		return fmt.Errorf("remove plugin %s: %w", id, err)
	}
	return r.reloadLocked()
}

func (r *Runtime) reloadLocked() error {
	summaries, hooks, err := loadRuntimeState(r.cfg, r.builtins)
	if err != nil {
		return err
	}
	r.registry.Replace(summaries)
	r.hooks.Replace(hooks)
	return nil
}

func loadRuntimeState(cfg config.PluginsConfig, builtins map[string]Summary) ([]Summary, []iam.Hook, error) {
	combined := &Registry{}
	for _, summary := range builtins {
		combined.Register(summary)
	}

	if !cfg.Enabled {
		return combined.List(), nil, nil
	}

	registry, err := NewRegistry(cfg)
	if err != nil {
		return nil, nil, err
	}
	for _, summary := range registry.List() {
		combined.Register(summary)
	}

	hooks, err := loadHooks(cfg)
	if err != nil {
		return nil, nil, err
	}
	return combined.List(), hooks, nil
}

func normalizeConfig(cfg config.PluginsConfig) config.PluginsConfig {
	directories := make([]string, 0, len(cfg.Directories))
	for _, directory := range cfg.Directories {
		directory = strings.TrimSpace(directory)
		if directory != "" {
			directories = append(directories, directory)
		}
	}
	if len(directories) == 0 {
		directories = []string{"plugins"}
	}
	cfg.Directories = directories
	return cfg
}

func loadHooks(cfg config.PluginsConfig) ([]iam.Hook, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	hooks := make([]iam.Hook, 0, len(cfg.HTTPActions))
	for _, action := range cfg.HTTPActions {
		if !action.Enabled {
			continue
		}
		hook, err := buildHTTPActionHook(cfg, action)
		if err != nil {
			return nil, err
		}
		if hook != nil {
			hooks = append(hooks, hook)
		}
	}

	enabledFilter := stringSet(cfg.EnabledPlugins)
	disabledFilter := stringSet(cfg.DisabledPlugins)
	for _, directory := range cfg.Directories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read plugin directory %q: %w", directory, err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			plugin, err := inspectLocalPluginDir(filepath.Join(directory, entry.Name()), cfg, enabledFilter, disabledFilter)
			if err != nil {
				return nil, err
			}
			if plugin == nil || !plugin.Enabled {
				continue
			}
			manifest := plugin.Manifest
			if manifest.Type != string(PluginTypeFlowAction) || manifest.HTTPAction == nil {
				continue
			}
			hook, err := buildHTTPActionHook(cfg, httpActionConfigFromManifest(manifest, plugin.State))
			if err != nil {
				return nil, fmt.Errorf("build plugin hook %s: %w", manifest.ID, err)
			}
			if hook != nil {
				hooks = append(hooks, hook)
			}
		}
	}
	return hooks, nil
}

func buildHTTPActionHook(cfg config.PluginsConfig, action config.HTTPActionConfig) (*iam.HTTPActionHook, error) {
	if !action.Enabled {
		return nil, nil
	}
	actionURL, err := validateRemoteURL(action.URL)
	if err != nil {
		return nil, fmt.Errorf("http action %s has invalid url: %w", strings.TrimSpace(action.ID), err)
	}
	if err := requireHostAllowed("http action", actionURL, cfg.AllowedActionHosts, len(cfg.AllowedActionHosts) == 0); err != nil {
		return nil, fmt.Errorf("http action %s: %w", strings.TrimSpace(action.ID), err)
	}
	client := newRestrictedHTTPClient(
		iam.HTTPActionTimeout(action.TimeoutMS),
		allowlistForRequest(actionURL.Host, cfg.AllowedActionHosts),
		cfg.AllowPrivateNetworks,
	)
	return iam.NewHTTPActionHookWithClient(action, client)
}

func (r *Runtime) primaryDirectory() (string, error) {
	for _, directory := range r.cfg.Directories {
		directory = strings.TrimSpace(directory)
		if directory != "" {
			if err := os.MkdirAll(directory, 0o755); err != nil {
				return "", fmt.Errorf("create plugin directory %q: %w", directory, err)
			}
			return directory, nil
		}
	}
	defaultDir := "plugins"
	if err := os.MkdirAll(defaultDir, 0o755); err != nil {
		return "", fmt.Errorf("create default plugin directory %q: %w", defaultDir, err)
	}
	return defaultDir, nil
}

func (r *Runtime) isManagedPath(candidate string) bool {
	candidate, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	for _, directory := range r.cfg.Directories {
		directory = strings.TrimSpace(directory)
		if directory == "" {
			continue
		}
		base, err := filepath.Abs(directory)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(base, candidate)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func parsePluginArchive(content []byte) (Manifest, string, *zip.Reader, error) {
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return Manifest{}, "", nil, fmt.Errorf("open plugin archive: %w", err)
	}
	if len(reader.File) == 0 {
		return Manifest{}, "", nil, fmt.Errorf("plugin archive is empty")
	}
	if len(reader.File) > maxPluginArchiveFiles {
		return Manifest{}, "", nil, fmt.Errorf("plugin archive contains too many files")
	}

	var manifestPath string
	for _, file := range reader.File {
		if file.UncompressedSize64 > maxPluginArchiveFileSize {
			return Manifest{}, "", nil, fmt.Errorf("plugin archive file %q exceeds the size limit", file.Name)
		}
		cleanName, ok := cleanArchivePath(file.Name)
		if !ok {
			return Manifest{}, "", nil, fmt.Errorf("plugin archive contains unsafe path %q", file.Name)
		}
		if isManifestFile(path.Base(cleanName)) {
			manifestPath = cleanName
			break
		}
	}
	if manifestPath == "" {
		return Manifest{}, "", nil, fmt.Errorf("plugin archive is missing a manifest file")
	}

	manifestFile := findArchiveFile(reader, manifestPath)
	if manifestFile == nil {
		return Manifest{}, "", nil, fmt.Errorf("plugin manifest %q was not found", manifestPath)
	}
	rc, err := manifestFile.Open()
	if err != nil {
		return Manifest{}, "", nil, fmt.Errorf("open plugin manifest %q: %w", manifestPath, err)
	}
	defer rc.Close()
	manifestContent, err := io.ReadAll(rc)
	if err != nil {
		return Manifest{}, "", nil, fmt.Errorf("read plugin manifest %q: %w", manifestPath, err)
	}
	manifest, err := LoadManifestContent(manifestContent, manifestPath)
	if err != nil {
		return Manifest{}, "", nil, err
	}
	rootPrefix := path.Dir(manifestPath)
	if rootPrefix == "." {
		rootPrefix = ""
	}
	return manifest, rootPrefix, reader, nil
}

func extractPluginArchive(reader *zip.Reader, rootPrefix, destination string) error {
	for _, file := range reader.File {
		cleanName, ok := cleanArchivePath(file.Name)
		if !ok {
			return fmt.Errorf("plugin archive contains unsafe path %q", file.Name)
		}
		relativeName, ok := archiveRelativePath(cleanName, rootPrefix)
		if !ok || relativeName == "" {
			continue
		}
		targetPath := filepath.Join(destination, filepath.FromSlash(relativeName))
		if !pathWithinBase(destination, targetPath) {
			return fmt.Errorf("plugin archive target %q escapes installation directory", relativeName)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("create plugin directory %q: %w", relativeName, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("create plugin file parent for %q: %w", relativeName, err)
		}
		src, err := file.Open()
		if err != nil {
			return fmt.Errorf("open plugin file %q: %w", relativeName, err)
		}
		mode := file.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		dst, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			src.Close()
			return fmt.Errorf("create plugin file %q: %w", relativeName, err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			src.Close()
			return fmt.Errorf("extract plugin file %q: %w", relativeName, err)
		}
		if err := dst.Close(); err != nil {
			src.Close()
			return fmt.Errorf("close plugin file %q: %w", relativeName, err)
		}
		if err := src.Close(); err != nil {
			return fmt.Errorf("close plugin source %q: %w", relativeName, err)
		}
	}
	return nil
}

func cleanArchivePath(raw string) (string, bool) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	raw = strings.TrimPrefix(raw, "/")
	if raw == "" {
		return "", false
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned == "" || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return cleaned, true
}

func archiveRelativePath(cleanName, rootPrefix string) (string, bool) {
	if rootPrefix == "" {
		return cleanName, true
	}
	if cleanName == rootPrefix {
		return "", false
	}
	if !strings.HasPrefix(cleanName, rootPrefix+"/") {
		return "", false
	}
	return strings.TrimPrefix(cleanName, rootPrefix+"/"), true
}

func pathWithinBase(base, candidate string) bool {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(baseAbs, candidateAbs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func findArchiveFile(reader *zip.Reader, target string) *zip.File {
	for _, file := range reader.File {
		cleanName, ok := cleanArchivePath(file.Name)
		if ok && cleanName == target {
			return file
		}
	}
	return nil
}

func isManifestFile(name string) bool {
	switch strings.TrimSpace(name) {
	case "mkauth-plugin.yaml", "plugin.yaml", "plugin.yml":
		return true
	default:
		return false
	}
}

func boolPtr(value bool) *bool {
	return &value
}
