package plugins

import (
	"fmt"
	"sort"
	"strings"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

const (
	PermissionNetworkHTTPAction = "network:http_action"

	permissionHookPrefix = "hook:"
)

func ValidateManifestPermissions(manifest Manifest, cfg config.PluginsConfig) error {
	declared := permissionSet(manifest.Permissions)
	for _, permission := range manifest.Permissions {
		if !isKnownPermission(permission) {
			return fmt.Errorf("plugin %s declares unsupported permission %q", manifest.ID, permission)
		}
	}

	required, err := requiredManifestPermissions(manifest)
	if err != nil {
		return err
	}
	for _, permission := range required {
		if _, ok := declared[permission]; !ok {
			return fmt.Errorf("plugin %s requires permission %q but does not declare it", manifest.ID, permission)
		}
	}
	if manifest.HTTPAction != nil {
		actionURL, err := validateRemoteURL(manifest.HTTPAction.URL)
		if err != nil {
			return fmt.Errorf("plugin %s has invalid http_action.url: %w", manifest.ID, err)
		}
		if err := requireHostAllowed("http action", actionURL, cfg.AllowedActionHosts, len(cfg.AllowedActionHosts) == 0); err != nil {
			return fmt.Errorf("plugin %s: %w", manifest.ID, err)
		}
	}

	allowed := permissionSet(cfg.AllowedPermissions)
	if len(allowed) == 0 {
		return nil
	}
	for _, permission := range manifest.Permissions {
		if _, ok := allowed[permission]; !ok {
			return fmt.Errorf("plugin %s permission %q is not allowed by server configuration", manifest.ID, permission)
		}
	}
	return nil
}

func requiredManifestPermissions(manifest Manifest) ([]string, error) {
	permissions := make([]string, 0, len(manifest.Events)+1)
	for _, event := range manifest.Events {
		event = strings.TrimSpace(event)
		if event == "" {
			continue
		}
		if !iam.IsSupportedHookEvent(event) {
			return nil, fmt.Errorf("plugin %s declares unsupported hook event %q", manifest.ID, event)
		}
		permissions = append(permissions, hookPermission(event))
	}
	if manifest.Entry == "http_action" || manifest.HTTPAction != nil {
		permissions = append(permissions, PermissionNetworkHTTPAction)
	}
	return normalizePermissionList(permissions), nil
}

func configuredHTTPActionPermissions(events []string) []string {
	permissions := []string{PermissionNetworkHTTPAction}
	for _, event := range normalizeEventList(events) {
		permissions = append(permissions, hookPermission(event))
	}
	return normalizePermissionList(permissions)
}

func validateCatalogPermissions(pluginID string, permissions []string, cfg config.PluginsConfig) error {
	allowed := permissionSet(cfg.AllowedPermissions)
	for _, permission := range permissions {
		if !isKnownPermission(permission) {
			return fmt.Errorf("plugin %s declares unsupported permission %q", pluginID, permission)
		}
		if len(allowed) > 0 {
			if _, ok := allowed[permission]; !ok {
				return fmt.Errorf("plugin %s permission %q is not allowed by server configuration", pluginID, permission)
			}
		}
	}
	return nil
}

func hookPermission(event string) string {
	return permissionHookPrefix + strings.TrimSpace(event)
}

func isKnownPermission(permission string) bool {
	permission = strings.TrimSpace(strings.ToLower(permission))
	if permission == PermissionNetworkHTTPAction {
		return true
	}
	if strings.HasPrefix(permission, permissionHookPrefix) {
		return iam.IsSupportedHookEvent(strings.TrimPrefix(permission, permissionHookPrefix))
	}
	return false
}

func normalizeEventList(items []string) []string {
	return normalizeStringList(items, false)
}

func normalizePermissionList(items []string) []string {
	permissions := normalizeStringList(items, true)
	sort.Strings(permissions)
	return permissions
}

func normalizeStringList(items []string, lower bool) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if lower {
			item = strings.ToLower(item)
		}
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	return normalized
}

func permissionSet(items []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, item := range normalizePermissionList(items) {
		set[item] = struct{}{}
	}
	return set
}
