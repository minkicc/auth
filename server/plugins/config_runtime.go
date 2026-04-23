package plugins

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"minki.cc/mkauth/server/config"
)

type ConfigView struct {
	PluginID   string            `json:"plugin_id"`
	Schema     []ConfigField     `json:"schema"`
	Values     map[string]string `json:"values"`
	Configured map[string]bool   `json:"configured"`
}

func (r *Runtime) GetConfig(id string) (ConfigView, error) {
	if r == nil {
		return ConfigView{}, fmt.Errorf("plugin runtime is not initialized")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	plugin, err := r.localPluginLocked(id)
	if err != nil {
		return ConfigView{}, err
	}
	return configViewForPlugin(plugin), nil
}

func (r *Runtime) SetConfig(id string, values map[string]string) (ConfigView, error) {
	return r.SetConfigWithActor(id, values, AuditActor{})
}

func (r *Runtime) SetConfigWithActor(id string, values map[string]string, actor AuditActor) (view ConfigView, err error) {
	if r == nil {
		return ConfigView{}, fmt.Errorf("plugin runtime is not initialized")
	}
	id = strings.TrimSpace(id)
	r.mu.Lock()
	defer r.mu.Unlock()
	var plugin *LocalPlugin
	defer func() {
		pluginName, version := "", ""
		if plugin != nil {
			pluginName = plugin.Manifest.Name
			version = plugin.Manifest.Version
		}
		r.appendAuditLocked(AuditEvent{
			Action:     "configure",
			PluginID:   id,
			PluginName: pluginName,
			Version:    version,
			Actor:      actor,
			Success:    err == nil,
			Error:      auditError(err),
			Details: map[string]string{
				"config_keys": strings.Join(sortedConfigKeys(values), ","),
			},
		})
	}()

	plugin, err = r.localPluginLocked(id)
	if err != nil {
		return ConfigView{}, err
	}
	previousState := clonePluginState(plugin.State)
	state := plugin.State
	if state == nil {
		now := pluginStateNow()
		state = &State{InstalledAt: now}
	}
	merged, err := validatePluginConfig(plugin.Manifest, r.cfg, values, state.Config)
	if err != nil {
		return ConfigView{}, err
	}
	state.Config = merged
	state.UpdatedAt = pluginStateNow()
	if err := SaveState(plugin.Directory, *state); err != nil {
		return ConfigView{}, err
	}
	if err := r.reloadLocked(); err != nil {
		if rollbackErr := restorePluginState(plugin.Directory, previousState); rollbackErr != nil {
			return ConfigView{}, fmt.Errorf("reload plugin runtime after config update: %w (rollback failed: %v)", err, rollbackErr)
		}
		_ = r.reloadLocked()
		return ConfigView{}, err
	}
	updated, err := r.localPluginLocked(id)
	if err != nil {
		return ConfigView{}, err
	}
	return configViewForPlugin(updated), nil
}

func (r *Runtime) localPluginLocked(id string) (*LocalPlugin, error) {
	summary, ok := r.registry.Get(id)
	if !ok {
		return nil, fmt.Errorf("plugin %s was not found", id)
	}
	if summary.Source != PluginSourceLocal || summary.Path == "" {
		return nil, fmt.Errorf("plugin %s is not a managed local plugin", id)
	}
	if !r.isManagedPath(summary.Path) {
		return nil, fmt.Errorf("plugin %s is outside managed plugin directories", id)
	}
	plugin, err := inspectLocalPluginDir(summary.Path, r.cfg, nil, nil)
	if err != nil {
		return nil, err
	}
	if plugin == nil {
		return nil, fmt.Errorf("plugin %s was not found", id)
	}
	return plugin, nil
}

func configViewForPlugin(plugin *LocalPlugin) ConfigView {
	if plugin == nil {
		return ConfigView{}
	}
	effective := effectivePluginConfig(plugin.Manifest, plugin.State)
	values := map[string]string{}
	configured := map[string]bool{}
	stateConfig := map[string]string{}
	if plugin.State != nil {
		stateConfig = plugin.State.Config
	}
	for _, field := range plugin.Manifest.ConfigSchema {
		value := effective[field.Key]
		if field.Sensitive {
			values[field.Key] = ""
		} else {
			values[field.Key] = value
		}
		if _, ok := stateConfig[field.Key]; ok {
			configured[field.Key] = true
		}
	}
	return ConfigView{
		PluginID:   plugin.Manifest.ID,
		Schema:     append([]ConfigField(nil), plugin.Manifest.ConfigSchema...),
		Values:     values,
		Configured: configured,
	}
}

func httpActionConfigFromManifest(manifest Manifest, state *State) config.HTTPActionConfig {
	action := config.HTTPActionConfig{
		ID:        manifest.ID,
		Name:      manifest.Name,
		Enabled:   true,
		Events:    append([]string(nil), manifest.Events...),
		URL:       manifest.HTTPAction.URL,
		Secret:    manifest.HTTPAction.Secret,
		TimeoutMS: manifest.HTTPAction.TimeoutMS,
		FailOpen:  manifest.HTTPAction.FailOpen,
	}
	values := effectivePluginConfig(manifest, state)
	if value := strings.TrimSpace(values["url"]); value != "" {
		action.URL = value
	}
	if value := strings.TrimSpace(values["secret"]); value != "" {
		action.Secret = value
	}
	secretEnv := strings.TrimSpace(manifest.HTTPAction.SecretEnv)
	if value := strings.TrimSpace(values["secret_env"]); value != "" {
		secretEnv = value
	}
	if action.Secret == "" && secretEnv != "" {
		action.Secret = strings.TrimSpace(os.Getenv(secretEnv))
	}
	if value := strings.TrimSpace(values["timeout_ms"]); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			action.TimeoutMS = parsed
		}
	}
	if value := strings.TrimSpace(values["fail_open"]); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			action.FailOpen = parsed
		}
	}
	return action
}

func sortedConfigKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		key = strings.TrimSpace(key)
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func pluginStateNow() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func clonePluginState(state *State) *State {
	if state == nil {
		return nil
	}
	cloned := *state
	if state.Enabled != nil {
		enabled := *state.Enabled
		cloned.Enabled = &enabled
	}
	if state.Config != nil {
		cloned.Config = make(map[string]string, len(state.Config))
		for key, value := range state.Config {
			cloned.Config[key] = value
		}
	}
	return &cloned
}

func restorePluginState(directory string, state *State) error {
	if state == nil {
		if err := os.Remove(filepath.Join(filepath.Clean(directory), StateFileName)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return SaveState(directory, *state)
}
