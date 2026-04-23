package plugins

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	BackupDirectoryName = ".mkauth-plugin-backups"
	BackupMetaFileName  = "mkauth-plugin.backup.yaml"
)

type BackupSummary struct {
	ID            string `json:"id" yaml:"id"`
	PluginID      string `json:"plugin_id" yaml:"plugin_id"`
	PluginName    string `json:"plugin_name,omitempty" yaml:"plugin_name,omitempty"`
	Version       string `json:"version,omitempty" yaml:"version,omitempty"`
	PackageSHA256 string `json:"package_sha256,omitempty" yaml:"package_sha256,omitempty"`
	Source        string `json:"source,omitempty" yaml:"source,omitempty"`
	Reason        string `json:"reason,omitempty" yaml:"reason,omitempty"`
	CreatedAt     string `json:"created_at" yaml:"created_at"`
	Path          string `json:"path,omitempty" yaml:"-"`
}

func (r *Runtime) ListBackups(pluginID string, limit int) ([]BackupSummary, error) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listBackupsLocked(pluginID, limit)
}

func (r *Runtime) listBackupsLocked(pluginID string, limit int) ([]BackupSummary, error) {
	root, err := r.backupRootLocked(false)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []BackupSummary{}, nil
		}
		return nil, fmt.Errorf("read plugin backups: %w", err)
	}
	pluginID = strings.TrimSpace(pluginID)
	backups := make([]BackupSummary, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		backup, err := loadBackupSummary(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		if backup == nil {
			continue
		}
		if pluginID != "" && backup.PluginID != pluginID {
			continue
		}
		backups = append(backups, *backup)
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt > backups[j].CreatedAt })
	if limit > 0 && len(backups) > limit {
		backups = backups[:limit]
	}
	return backups, nil
}

func (r *Runtime) RestoreBackup(id string) (Summary, error) {
	return r.RestoreBackupWithActor(id, AuditActor{})
}

func (r *Runtime) RestoreBackupWithActor(id string, actor AuditActor) (summary Summary, err error) {
	if r == nil {
		return Summary{}, fmt.Errorf("plugin runtime is not initialized")
	}
	id = strings.TrimSpace(id)
	r.mu.Lock()
	defer r.mu.Unlock()

	var backup *BackupSummary
	var previousDetails map[string]string
	defer func() {
		pluginID := ""
		if backup != nil {
			pluginID = backup.PluginID
		}
		if summary.ID != "" {
			pluginID = summary.ID
		}
		r.appendAuditLocked(AuditEvent{
			Action:     "restore",
			PluginID:   pluginID,
			PluginName: summary.Name,
			Version:    summary.Version,
			Source:     "backup:" + id,
			Actor:      actor,
			Success:    err == nil,
			Error:      auditError(err),
			Details: mergeAuditDetails(auditSummaryDetails(summary), previousDetails, map[string]string{
				"backup_id": id,
			}),
		})
	}()

	backup, err = r.findBackupLocked(id)
	if err != nil {
		return Summary{}, err
	}
	if backup == nil {
		return Summary{}, fmt.Errorf("plugin backup %s was not found", id)
	}
	installDir, err := r.primaryDirectory()
	if err != nil {
		return Summary{}, err
	}
	targetDir := filepath.Join(installDir, backup.PluginID)
	if current, ok := r.registry.Get(backup.PluginID); ok {
		previousDetails = auditPreviousSummaryDetails(current)
	}

	tempDir, err := os.MkdirTemp(installDir, backup.PluginID+".restore-*")
	if err != nil {
		return Summary{}, fmt.Errorf("create temporary restore directory: %w", err)
	}
	defer os.RemoveAll(tempDir)
	if err := copyPluginDirectory(backup.Path, tempDir, map[string]struct{}{BackupMetaFileName: {}}); err != nil {
		return Summary{}, err
	}
	if _, err := inspectLocalPluginDir(tempDir, r.cfg, nil, nil); err != nil {
		return Summary{}, err
	}
	if state, err := LoadState(tempDir); err == nil && state != nil {
		state.Source = "restore:" + backup.ID
		state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := SaveState(tempDir, *state); err != nil {
			return Summary{}, err
		}
	}
	if _, err := os.Stat(targetDir); err == nil {
		current := Summary{ID: backup.PluginID, Path: targetDir}
		if registrySummary, ok := r.registry.Get(backup.PluginID); ok {
			current = registrySummary
		}
		if _, err := r.createBackupLocked(current, "restore_replace"); err != nil {
			return Summary{}, err
		}
		if err := os.RemoveAll(targetDir); err != nil {
			return Summary{}, fmt.Errorf("remove current plugin %s before restore: %w", backup.PluginID, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return Summary{}, fmt.Errorf("inspect plugin %s before restore: %w", backup.PluginID, err)
	}
	if err := os.Rename(tempDir, targetDir); err != nil {
		return Summary{}, fmt.Errorf("restore plugin %s: %w", backup.PluginID, err)
	}
	if err := r.reloadLocked(); err != nil {
		return Summary{}, err
	}
	restored, ok := r.registry.Get(backup.PluginID)
	if !ok {
		return Summary{}, fmt.Errorf("plugin %s was restored but not loaded", backup.PluginID)
	}
	return restored, nil
}

func (r *Runtime) createBackupLocked(summary Summary, reason string) (*BackupSummary, error) {
	if strings.TrimSpace(summary.ID) == "" || strings.TrimSpace(summary.Path) == "" {
		return nil, nil
	}
	if !r.isManagedPath(summary.Path) {
		return nil, fmt.Errorf("plugin %s is outside managed plugin directories", summary.ID)
	}
	if _, err := os.Stat(summary.Path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect plugin %s before backup: %w", summary.ID, err)
	}
	root, err := r.backupRootLocked(true)
	if err != nil {
		return nil, err
	}
	backup := BackupSummary{
		ID:            safeBackupID(summary.ID),
		PluginID:      summary.ID,
		PluginName:    summary.Name,
		Version:       summary.Version,
		PackageSHA256: summary.PackageSHA256,
		Source:        string(summary.Source),
		Reason:        strings.TrimSpace(reason),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	backup.Path = filepath.Join(root, backup.ID)
	if err := copyPluginDirectory(summary.Path, backup.Path, nil); err != nil {
		return nil, err
	}
	if err := saveBackupSummary(backup.Path, backup); err != nil {
		return nil, err
	}
	return &backup, nil
}

func (r *Runtime) findBackupLocked(id string) (*BackupSummary, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("backup id is required")
	}
	if id != filepath.Base(id) {
		return nil, fmt.Errorf("backup id %q is invalid", id)
	}
	root, err := r.backupRootLocked(false)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, id)
	if !pathWithinBase(root, path) {
		return nil, fmt.Errorf("backup id %q is invalid", id)
	}
	return loadBackupSummary(path)
}

func (r *Runtime) backupRootLocked(create bool) (string, error) {
	directory := ""
	if create {
		var err error
		directory, err = r.primaryDirectory()
		if err != nil {
			return "", err
		}
	} else {
		for _, item := range r.cfg.Directories {
			item = strings.TrimSpace(item)
			if item != "" {
				directory = item
				break
			}
		}
		if directory == "" {
			directory = "plugins"
		}
	}
	root := filepath.Join(directory, BackupDirectoryName)
	if create {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", fmt.Errorf("create plugin backup directory: %w", err)
		}
	}
	return root, nil
}

func loadBackupSummary(directory string) (*BackupSummary, error) {
	content, err := os.ReadFile(filepath.Join(directory, BackupMetaFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin backup metadata: %w", err)
	}
	var backup BackupSummary
	if err := yaml.Unmarshal(content, &backup); err != nil {
		return nil, fmt.Errorf("parse plugin backup metadata: %w", err)
	}
	backup.ID = strings.TrimSpace(backup.ID)
	backup.PluginID = strings.TrimSpace(backup.PluginID)
	if backup.ID == "" || backup.PluginID == "" {
		return nil, fmt.Errorf("plugin backup metadata in %q is incomplete", directory)
	}
	backup.Path = directory
	return &backup, nil
}

func saveBackupSummary(directory string, backup BackupSummary) error {
	content, err := yaml.Marshal(backup)
	if err != nil {
		return fmt.Errorf("marshal plugin backup metadata: %w", err)
	}
	if err := os.WriteFile(filepath.Join(directory, BackupMetaFileName), content, 0o600); err != nil {
		return fmt.Errorf("write plugin backup metadata: %w", err)
	}
	return nil
}

func safeBackupID(pluginID string) string {
	pluginID = strings.TrimSpace(pluginID)
	if pluginID == "" {
		pluginID = "plugin"
	}
	id := strings.NewReplacer(".", "-", "_", "-", ":", "-").Replace(newAuditID())
	return pluginID + "-" + id
}

func copyPluginDirectory(source, destination string, skipNames map[string]struct{}) error {
	source = filepath.Clean(source)
	destination = filepath.Clean(destination)
	if source == "." || destination == "." || source == destination {
		return fmt.Errorf("invalid plugin copy path")
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return fmt.Errorf("create plugin copy destination: %w", err)
	}
	return filepath.WalkDir(source, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if _, skip := skipNames[entry.Name()]; skip {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(destination, relative)
		if !pathWithinBase(destination, target) {
			return fmt.Errorf("plugin copy target %q escapes destination", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("plugin backup refuses symlink %q", relative)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		return copyPluginFile(current, target, info.Mode().Perm())
	})
}

func copyPluginFile(source, destination string, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o644
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}
