package oidc

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/secureconfig"
)

// ClientRecord stores admin-managed OIDC relying party clients.
type ClientRecord struct {
	ClientID   string    `json:"client_id" gorm:"primaryKey;size:120"`
	Name       string    `json:"name,omitempty" gorm:"size:120"`
	Enabled    bool      `json:"enabled" gorm:"not null"`
	ConfigJSON string    `json:"config_json,omitempty" gorm:"type:text"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (ClientRecord) TableName() string {
	return "oidc_clients"
}

func autoMigrateClientRecords(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("oidc client store requires database")
	}
	return db.AutoMigrate(&ClientRecord{})
}

func NormalizeClientConfig(client config.OIDCClientConfig) config.OIDCClientConfig {
	client.Name = strings.TrimSpace(client.Name)
	client.ClientID = strings.TrimSpace(client.ClientID)
	client.ClientSecret = strings.TrimSpace(client.ClientSecret)
	client.RedirectURIs = normalizeUniqueStrings(client.RedirectURIs, false)
	client.Scopes = normalizeUniqueStrings(client.Scopes, true)
	client.OIDCOrganizationPolicy = normalizeOrganizationPolicy(client.OIDCOrganizationPolicy)
	client.ScopePolicies = normalizeScopePolicies(client.ScopePolicies)
	return client
}

func ValidateClientConfig(client config.OIDCClientConfig) error {
	client = NormalizeClientConfig(client)
	if client.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if len(client.RedirectURIs) == 0 {
		return fmt.Errorf("client %s must define at least one redirect_uri", client.ClientID)
	}
	for _, redirectURI := range client.RedirectURIs {
		parsed, err := url.Parse(strings.TrimSpace(redirectURI))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("client %s has invalid redirect_uri %q", client.ClientID, redirectURI)
		}
	}
	if !client.Public && client.ClientSecret == "" {
		return fmt.Errorf("confidential client %s must define client_secret", client.ClientID)
	}
	allowedScopes := effectiveAllowedScopes(client)
	allowedScopeSet := make(map[string]struct{}, len(allowedScopes))
	for _, scope := range allowedScopes {
		allowedScopeSet[scope] = struct{}{}
	}
	for scope := range client.ScopePolicies {
		if _, ok := allowedScopeSet[scope]; !ok {
			return fmt.Errorf("client %s has scope policy for unsupported scope %q", client.ClientID, scope)
		}
	}
	return nil
}

func ClientRecordFromConfig(client config.OIDCClientConfig, enabled bool) (ClientRecord, error) {
	client = NormalizeClientConfig(client)
	if err := ValidateClientConfig(client); err != nil {
		return ClientRecord{}, err
	}
	storedConfig, err := secureconfig.SealJSON(client)
	if err != nil {
		return ClientRecord{}, fmt.Errorf("encode oidc client config: %w", err)
	}
	return ClientRecord{
		ClientID:   client.ClientID,
		Name:       client.Name,
		Enabled:    enabled,
		ConfigJSON: storedConfig,
	}, nil
}

func ClientConfigFromRecord(record ClientRecord) (config.OIDCClientConfig, error) {
	var client config.OIDCClientConfig
	if strings.TrimSpace(record.ConfigJSON) != "" {
		if err := secureconfig.OpenJSON(record.ConfigJSON, &client); err != nil {
			return config.OIDCClientConfig{}, fmt.Errorf("decode oidc client %s: %w", record.ClientID, err)
		}
	}
	client.ClientID = strings.TrimSpace(record.ClientID)
	if strings.TrimSpace(record.Name) != "" {
		client.Name = strings.TrimSpace(record.Name)
	}
	client = NormalizeClientConfig(client)
	if err := ValidateClientConfig(client); err != nil {
		return config.OIDCClientConfig{}, err
	}
	return client, nil
}

func normalizeUniqueStrings(values []string, lower bool) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if lower {
			value = strings.ToLower(value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeUniqueFoldStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Slice(normalized, func(i, j int) bool {
		return strings.ToLower(normalized[i]) < strings.ToLower(normalized[j])
	})
	return normalized
}

func normalizeOrganizationPolicy(policy config.OIDCOrganizationPolicy) config.OIDCOrganizationPolicy {
	policy.AllowedOrganizations = normalizeUniqueFoldStrings(policy.AllowedOrganizations)
	policy.RequiredOrgRoles = normalizeUniqueStrings(policy.RequiredOrgRoles, true)
	policy.RequiredOrgRolesAll = normalizeUniqueStrings(policy.RequiredOrgRolesAll, true)
	policy.RequiredOrgGroups = normalizeUniqueStrings(policy.RequiredOrgGroups, true)
	policy.RequiredOrgGroupsAll = normalizeUniqueStrings(policy.RequiredOrgGroupsAll, true)
	return policy
}

func normalizeScopePolicies(raw map[string]config.OIDCOrganizationPolicy) map[string]config.OIDCOrganizationPolicy {
	if len(raw) == 0 {
		return nil
	}
	normalized := make(map[string]config.OIDCOrganizationPolicy, len(raw))
	for scope, policy := range raw {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		policy = normalizeOrganizationPolicy(policy)
		if !organizationPolicyConfigured(policy) {
			continue
		}
		normalized[scope] = policy
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func effectiveAllowedScopes(client config.OIDCClientConfig) []string {
	if len(client.Scopes) == 0 {
		return append([]string(nil), defaultScopes...)
	}
	return append([]string(nil), client.Scopes...)
}

func organizationPolicyConfigured(policy config.OIDCOrganizationPolicy) bool {
	return policy.RequireOrganization ||
		len(policy.AllowedOrganizations) > 0 ||
		len(policy.RequiredOrgRoles) > 0 ||
		len(policy.RequiredOrgRolesAll) > 0 ||
		len(policy.RequiredOrgGroups) > 0 ||
		len(policy.RequiredOrgGroupsAll) > 0
}
