package plugins

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"minki.cc/mkauth/server/config"
)

const (
	ConfigTypeString  = "string"
	ConfigTypeText    = "text"
	ConfigTypeURL     = "url"
	ConfigTypeSecret  = "secret"
	ConfigTypeInteger = "integer"
	ConfigTypeBoolean = "boolean"
	ConfigTypeSelect  = "select"
)

var configKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

func normalizeConfigSchema(fields []ConfigField) []ConfigField {
	if len(fields) == 0 {
		return nil
	}
	normalized := make([]ConfigField, 0, len(fields))
	for _, field := range fields {
		field.Key = strings.TrimSpace(strings.ToLower(field.Key))
		field.Label = strings.TrimSpace(field.Label)
		field.Type = strings.TrimSpace(strings.ToLower(field.Type))
		if field.Type == "" {
			field.Type = ConfigTypeString
		}
		field.Description = strings.TrimSpace(field.Description)
		field.Default = strings.TrimSpace(field.Default)
		field.Options = normalizeStringList(field.Options, false)
		if field.Label == "" {
			field.Label = field.Key
		}
		if field.Type == ConfigTypeSecret {
			field.Sensitive = true
		}
		normalized = append(normalized, field)
	}
	return normalized
}

func validateConfigSchema(fields []ConfigField, path string) error {
	seen := map[string]struct{}{}
	for _, field := range fields {
		if !configKeyPattern.MatchString(field.Key) {
			return fmt.Errorf("plugin manifest %q has invalid config key %q", path, field.Key)
		}
		if _, ok := seen[field.Key]; ok {
			return fmt.Errorf("plugin manifest %q has duplicate config key %q", path, field.Key)
		}
		seen[field.Key] = struct{}{}
		if !isSupportedConfigType(field.Type) {
			return fmt.Errorf("plugin manifest %q has unsupported config type %q for key %q", path, field.Type, field.Key)
		}
		if field.Type == ConfigTypeSelect && len(field.Options) == 0 {
			return fmt.Errorf("plugin manifest %q select config %q must define options", path, field.Key)
		}
		if field.Default != "" {
			if err := validateConfigFieldValue(field, field.Default, config.PluginsConfig{}); err != nil {
				return fmt.Errorf("plugin manifest %q default for config %q is invalid: %w", path, field.Key, err)
			}
		}
	}
	return nil
}

func isSupportedConfigType(kind string) bool {
	switch strings.TrimSpace(kind) {
	case ConfigTypeString, ConfigTypeText, ConfigTypeURL, ConfigTypeSecret, ConfigTypeInteger, ConfigTypeBoolean, ConfigTypeSelect:
		return true
	default:
		return false
	}
}

func effectivePluginConfig(manifest Manifest, state *State) map[string]string {
	values := map[string]string{}
	schema := configSchemaMap(manifest.ConfigSchema)
	for _, field := range manifest.ConfigSchema {
		if field.Default != "" {
			values[field.Key] = field.Default
		}
	}
	if state != nil {
		for key, value := range state.Config {
			key = strings.TrimSpace(strings.ToLower(key))
			if _, ok := schema[key]; ok {
				values[key] = strings.TrimSpace(value)
			}
		}
	}
	return values
}

func validatePluginConfig(manifest Manifest, cfg config.PluginsConfig, next, existing map[string]string) (map[string]string, error) {
	schema := configSchemaMap(manifest.ConfigSchema)
	if len(schema) == 0 && len(next) > 0 {
		return nil, fmt.Errorf("plugin %s does not declare configurable fields", manifest.ID)
	}
	merged := map[string]string{}
	for key, value := range existing {
		key = strings.TrimSpace(strings.ToLower(key))
		if _, ok := schema[key]; ok {
			merged[key] = strings.TrimSpace(value)
		}
	}
	for rawKey, rawValue := range next {
		key := strings.TrimSpace(strings.ToLower(rawKey))
		if key == "" {
			continue
		}
		field, ok := schema[key]
		if !ok {
			return nil, fmt.Errorf("plugin %s does not support config key %q", manifest.ID, rawKey)
		}
		value := strings.TrimSpace(rawValue)
		if field.Sensitive && value == "" {
			continue
		}
		merged[key] = value
	}
	effective := effectivePluginConfig(manifest, &State{Config: merged})
	for _, field := range manifest.ConfigSchema {
		value := strings.TrimSpace(effective[field.Key])
		if field.Required && value == "" {
			return nil, fmt.Errorf("plugin %s config %q is required", manifest.ID, field.Key)
		}
		if value == "" {
			continue
		}
		if err := validateConfigFieldValue(field, value, cfg); err != nil {
			return nil, fmt.Errorf("plugin %s config %q is invalid: %w", manifest.ID, field.Key, err)
		}
	}
	if manifest.HTTPAction != nil {
		action := httpActionConfigFromManifest(manifest, &State{Config: merged})
		actionURL, err := validateRemoteURL(action.URL)
		if err != nil {
			return nil, fmt.Errorf("plugin %s http_action.url is invalid: %w", manifest.ID, err)
		}
		if err := requireHostAllowed("http action", actionURL, cfg.AllowedActionHosts, len(cfg.AllowedActionHosts) == 0); err != nil {
			return nil, fmt.Errorf("plugin %s: %w", manifest.ID, err)
		}
	}
	return merged, nil
}

func validateConfigFieldValue(field ConfigField, value string, cfg config.PluginsConfig) error {
	switch field.Type {
	case ConfigTypeString, ConfigTypeText, ConfigTypeSecret:
		return nil
	case ConfigTypeURL:
		parsed, err := validateRemoteURL(value)
		if err != nil {
			return err
		}
		return requireHostAllowed("config url", parsed, cfg.AllowedActionHosts, len(cfg.AllowedActionHosts) == 0)
	case ConfigTypeInteger:
		_, err := strconv.Atoi(value)
		return err
	case ConfigTypeBoolean:
		_, err := strconv.ParseBool(value)
		return err
	case ConfigTypeSelect:
		for _, option := range field.Options {
			if value == option {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(field.Options, ", "))
	default:
		return fmt.Errorf("unsupported config type %q", field.Type)
	}
}

func configSchemaMap(fields []ConfigField) map[string]ConfigField {
	items := map[string]ConfigField{}
	for _, field := range fields {
		items[field.Key] = field
	}
	return items
}

func hasConfiguredPluginConfig(manifest Manifest, state *State) bool {
	if state == nil || len(state.Config) == 0 || len(manifest.ConfigSchema) == 0 {
		return false
	}
	schema := configSchemaMap(manifest.ConfigSchema)
	for key := range state.Config {
		key = strings.TrimSpace(strings.ToLower(key))
		if _, ok := schema[key]; ok {
			return true
		}
	}
	return false
}
