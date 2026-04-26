package plugins

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"minki.cc/mkauth/server/iam"
)

var claimNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_:.~-]{0,127}$`)
var claimTemplatePattern = regexp.MustCompile(`\$\{([^}]+)\}`)

var protectedClaimNames = map[string]struct{}{
	"iss":             {},
	"sub":             {},
	"aud":             {},
	"exp":             {},
	"iat":             {},
	"nbf":             {},
	"jti":             {},
	"nonce":           {},
	"scope":           {},
	"client_id":       {},
	"token_type":      {},
	"token_version":   {},
	"grant_type":      {},
	"subject_type":    {},
	"service_account": {},
	"org_id":          {},
	"org_slug":        {},
	"org_roles":       {},
	"org_groups":      {},
}

func normalizeClaimMappings(mappings []ClaimMapping) []ClaimMapping {
	if len(mappings) == 0 {
		return nil
	}
	normalized := make([]ClaimMapping, 0, len(mappings))
	for _, mapping := range mappings {
		mapping.Claim = strings.TrimSpace(mapping.Claim)
		mapping.Value = strings.TrimSpace(mapping.Value)
		mapping.ValueFrom = strings.TrimSpace(strings.ToLower(mapping.ValueFrom))
		mapping.Clients = normalizeStringList(mapping.Clients, false)
		mapping.Organizations = normalizeStringList(mapping.Organizations, false)
		normalized = append(normalized, mapping)
	}
	return normalized
}

func validateClaimMappings(manifest Manifest, path string) error {
	if manifest.Type != string(PluginTypeClaimMapper) {
		if len(manifest.ClaimMappings) > 0 {
			return fmt.Errorf("plugin manifest %q declares claim_mappings but is not type %q", path, PluginTypeClaimMapper)
		}
		return nil
	}
	if len(manifest.ClaimMappings) == 0 {
		return fmt.Errorf("plugin manifest %q type %q requires at least one claim mapping", path, PluginTypeClaimMapper)
	}
	for _, event := range manifest.Events {
		switch iam.HookEvent(event) {
		case iam.HookBeforeTokenIssue, iam.HookBeforeUserInfo:
		default:
			return fmt.Errorf("plugin manifest %q claim mapper event %q is unsupported", path, event)
		}
	}
	for _, mapping := range manifest.ClaimMappings {
		if mapping.Claim == "" {
			return fmt.Errorf("plugin manifest %q claim mapping is missing claim", path)
		}
		if !claimNamePattern.MatchString(mapping.Claim) {
			return fmt.Errorf("plugin manifest %q claim mapping has invalid claim %q", path, mapping.Claim)
		}
		if _, protected := protectedClaimNames[strings.ToLower(mapping.Claim)]; protected {
			return fmt.Errorf("plugin manifest %q claim mapping cannot write protected claim %q", path, mapping.Claim)
		}
		if mapping.Value != "" && mapping.ValueFrom != "" {
			return fmt.Errorf("plugin manifest %q claim mapping %q cannot define both value and value_from", path, mapping.Claim)
		}
		if mapping.Value == "" && mapping.ValueFrom == "" {
			return fmt.Errorf("plugin manifest %q claim mapping %q requires value or value_from", path, mapping.Claim)
		}
	}
	return nil
}

func buildClaimMapperHook(manifest Manifest, state *State) (iam.Hook, error) {
	if manifest.Type != string(PluginTypeClaimMapper) {
		return nil, nil
	}
	if len(manifest.Events) == 0 || len(manifest.ClaimMappings) == 0 {
		return nil, nil
	}

	events := map[iam.HookEvent]struct{}{}
	for _, event := range manifest.Events {
		events[iam.HookEvent(event)] = struct{}{}
	}
	configValues := effectivePluginConfig(manifest, state)
	mappings := append([]ClaimMapping(nil), manifest.ClaimMappings...)

	return iam.HookFunc{
		HookName: manifest.ID,
		Fn: func(ctx context.Context, event iam.HookEvent, data *iam.HookContext) error {
			if _, ok := events[event]; !ok {
				return nil
			}
			if data == nil {
				data = &iam.HookContext{}
			}
			if data.Claims == nil {
				data.Claims = map[string]any{}
			}
			for _, mapping := range mappings {
				if !claimMappingApplies(mapping, data) {
					continue
				}
				value, ok := claimMappingValue(mapping, manifest, configValues, data, event)
				if ok {
					data.Claims[mapping.Claim] = value
				}
			}
			return nil
		},
	}, nil
}

func claimMappingApplies(mapping ClaimMapping, data *iam.HookContext) bool {
	if len(mapping.Clients) > 0 && !matchesAnyFold(data.ClientID, mapping.Clients) {
		return false
	}
	if len(mapping.Organizations) > 0 {
		organizationID := strings.TrimSpace(data.OrganizationID)
		if organizationID == "" {
			organizationID, _ = claimString(data.Claims, "org_id")
		}
		organizationSlug, _ := claimString(data.Claims, "org_slug")
		if !matchesAnyFold(organizationID, mapping.Organizations) && !matchesAnyFold(organizationSlug, mapping.Organizations) {
			return false
		}
	}
	return true
}

func claimMappingValue(mapping ClaimMapping, manifest Manifest, configValues map[string]string, data *iam.HookContext, event iam.HookEvent) (any, bool) {
	if mapping.ValueFrom != "" {
		return claimValueFrom(mapping.ValueFrom, manifest, configValues, data, event)
	}
	return renderClaimTemplate(mapping.Value, manifest, configValues, data, event), true
}

func claimValueFrom(source string, manifest Manifest, configValues map[string]string, data *iam.HookContext, event iam.HookEvent) (any, bool) {
	switch source {
	case "plugin.id":
		return manifest.ID, true
	case "plugin.name":
		return manifest.Name, true
	case "plugin.version":
		return manifest.Version, true
	case "event":
		return string(event), true
	case "client_id":
		return data.ClientID, data.ClientID != ""
	case "organization_id":
		if strings.TrimSpace(data.OrganizationID) != "" {
			return data.OrganizationID, true
		}
		return claimString(data.Claims, "org_id")
	case "user.user_id":
		if data.User != nil {
			return data.User.UserID, data.User.UserID != ""
		}
	case "user.username":
		if data.User != nil {
			return data.User.Username, data.User.Username != ""
		}
	case "user.nickname":
		if data.User != nil {
			return data.User.Nickname, data.User.Nickname != ""
		}
	case "user.avatar":
		if data.User != nil {
			return data.User.Avatar, data.User.Avatar != ""
		}
	case "user.status":
		if data.User != nil {
			status := string(data.User.Status)
			return status, status != ""
		}
	}

	if strings.HasPrefix(source, "claim.") {
		key := strings.TrimSpace(strings.TrimPrefix(source, "claim."))
		if key == "" || data.Claims == nil {
			return nil, false
		}
		value, ok := data.Claims[key]
		return value, ok
	}
	if strings.HasPrefix(source, "metadata.") {
		key := strings.TrimSpace(strings.TrimPrefix(source, "metadata."))
		if key == "" || data.Metadata == nil {
			return nil, false
		}
		value, ok := data.Metadata[key]
		return value, ok && value != ""
	}
	if strings.HasPrefix(source, "config.") {
		key := strings.TrimSpace(strings.TrimPrefix(source, "config."))
		if key == "" {
			return nil, false
		}
		value, ok := configValues[key]
		return value, ok && value != ""
	}
	return nil, false
}

func renderClaimTemplate(template string, manifest Manifest, configValues map[string]string, data *iam.HookContext, event iam.HookEvent) string {
	return claimTemplatePattern.ReplaceAllStringFunc(template, func(raw string) string {
		matches := claimTemplatePattern.FindStringSubmatch(raw)
		if len(matches) != 2 {
			return raw
		}
		value, ok := claimValueFrom(strings.TrimSpace(strings.ToLower(matches[1])), manifest, configValues, data, event)
		if !ok {
			return ""
		}
		return fmt.Sprint(value)
	})
}

func claimString(claims map[string]any, key string) (string, bool) {
	if claims == nil {
		return "", false
	}
	value, ok := claims[key]
	if !ok {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return typed, typed != ""
	default:
		return fmt.Sprint(typed), typed != nil
	}
}

func matchesAnyFold(value string, candidates []string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, candidate := range candidates {
		if strings.EqualFold(value, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}
