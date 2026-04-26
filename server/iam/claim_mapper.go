package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gorm.io/gorm"
)

var claimMapperNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_:.~-]{0,127}$`)
var claimMapperTemplatePattern = regexp.MustCompile(`\$\{([^}]+)\}`)

var protectedClaimMapperNames = map[string]struct{}{
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

type ClaimMapperRuleSpec struct {
	Name          string
	Description   string
	Enabled       bool
	Claim         string
	Value         string
	ValueFrom     string
	Events        []string
	Clients       []string
	Organizations []string
}

func ClaimMapperRuleFromSpec(mapperID string, spec ClaimMapperRuleSpec, existing *ClaimMapperRule) (ClaimMapperRule, error) {
	normalized, err := NormalizeClaimMapperRuleSpec(spec)
	if err != nil {
		return ClaimMapperRule{}, err
	}
	rule := ClaimMapperRule{}
	if existing != nil {
		rule = *existing
	}
	rule.MapperID = strings.TrimSpace(mapperID)
	if rule.MapperID == "" && existing != nil {
		rule.MapperID = existing.MapperID
	}
	if rule.MapperID == "" {
		return ClaimMapperRule{}, fmt.Errorf("claim mapper id is required")
	}
	rule.Name = normalized.Name
	rule.Description = normalized.Description
	rule.Enabled = normalized.Enabled
	rule.Claim = normalized.Claim
	rule.Value = normalized.Value
	rule.ValueFrom = normalized.ValueFrom
	rule.EventsJSON = mustMarshalClaimMapperStrings(normalized.Events)
	rule.ClientIDsJSON = mustMarshalClaimMapperStrings(normalized.Clients)
	rule.OrganizationsJSON = mustMarshalClaimMapperStrings(normalized.Organizations)
	return rule, nil
}

func NormalizeClaimMapperRuleSpec(spec ClaimMapperRuleSpec) (ClaimMapperRuleSpec, error) {
	spec.Name = strings.TrimSpace(spec.Name)
	spec.Description = strings.TrimSpace(spec.Description)
	spec.Claim = strings.TrimSpace(spec.Claim)
	spec.Value = strings.TrimSpace(spec.Value)
	spec.ValueFrom = strings.TrimSpace(strings.ToLower(spec.ValueFrom))
	spec.Events = normalizeClaimMapperEvents(spec.Events)
	spec.Clients = normalizeClaimMapperStringList(spec.Clients, false)
	spec.Organizations = normalizeClaimMapperStringList(spec.Organizations, false)

	if spec.Name == "" {
		spec.Name = spec.Claim
	}
	if spec.Name == "" {
		return ClaimMapperRuleSpec{}, fmt.Errorf("name is required")
	}
	if spec.Claim == "" {
		return ClaimMapperRuleSpec{}, fmt.Errorf("claim is required")
	}
	if !claimMapperNamePattern.MatchString(spec.Claim) {
		return ClaimMapperRuleSpec{}, fmt.Errorf("claim %q is invalid", spec.Claim)
	}
	if _, protected := protectedClaimMapperNames[strings.ToLower(spec.Claim)]; protected {
		return ClaimMapperRuleSpec{}, fmt.Errorf("claim %q is protected", spec.Claim)
	}
	if spec.Value != "" && spec.ValueFrom != "" {
		return ClaimMapperRuleSpec{}, fmt.Errorf("claim mapper cannot define both value and value_from")
	}
	if spec.Value == "" && spec.ValueFrom == "" {
		return ClaimMapperRuleSpec{}, fmt.Errorf("claim mapper requires value or value_from")
	}
	for _, event := range spec.Events {
		switch HookEvent(event) {
		case HookBeforeTokenIssue, HookBeforeUserInfo:
		default:
			return ClaimMapperRuleSpec{}, fmt.Errorf("claim mapper event %q is unsupported", event)
		}
	}
	return spec, nil
}

func SpecFromClaimMapperRule(rule ClaimMapperRule) ClaimMapperRuleSpec {
	return ClaimMapperRuleSpec{
		Name:          rule.Name,
		Description:   rule.Description,
		Enabled:       rule.Enabled,
		Claim:         rule.Claim,
		Value:         rule.Value,
		ValueFrom:     rule.ValueFrom,
		Events:        claimMapperStringsFromJSON(rule.EventsJSON),
		Clients:       claimMapperStringsFromJSON(rule.ClientIDsJSON),
		Organizations: claimMapperStringsFromJSON(rule.OrganizationsJSON),
	}
}

func NewDatabaseClaimMapperHook(db *gorm.DB) Hook {
	return HookFunc{
		HookName: "database_claim_mappers",
		Fn: func(ctx context.Context, event HookEvent, data *HookContext) error {
			if db == nil {
				return nil
			}
			switch event {
			case HookBeforeTokenIssue, HookBeforeUserInfo:
			default:
				return nil
			}
			if !db.Migrator().HasTable(&ClaimMapperRule{}) {
				return nil
			}
			var rules []ClaimMapperRule
			if err := db.WithContext(ctx).
				Where("enabled = ?", true).
				Order("created_at ASC, mapper_id ASC").
				Find(&rules).Error; err != nil {
				return err
			}
			if data == nil {
				data = &HookContext{}
			}
			if data.Claims == nil {
				data.Claims = map[string]any{}
			}
			for _, rule := range rules {
				spec, err := NormalizeClaimMapperRuleSpec(SpecFromClaimMapperRule(rule))
				if err != nil {
					continue
				}
				if !claimMapperEventEnabled(spec.Events, event) || !claimMapperApplies(spec, data) {
					continue
				}
				value, ok := claimMapperValue(rule, spec, data, event)
				if ok {
					data.Claims[spec.Claim] = value
				}
			}
			return nil
		},
	}
}

func claimMapperEventEnabled(events []string, event HookEvent) bool {
	for _, item := range events {
		if HookEvent(item) == event {
			return true
		}
	}
	return false
}

func claimMapperApplies(spec ClaimMapperRuleSpec, data *HookContext) bool {
	if len(spec.Clients) > 0 && !claimMapperMatchesAnyFold(data.ClientID, spec.Clients) {
		return false
	}
	if len(spec.Organizations) > 0 {
		organizationID := strings.TrimSpace(data.OrganizationID)
		if organizationID == "" {
			organizationID, _ = claimMapperClaimString(data.Claims, "org_id")
		}
		organizationSlug, _ := claimMapperClaimString(data.Claims, "org_slug")
		if !claimMapperMatchesAnyFold(organizationID, spec.Organizations) && !claimMapperMatchesAnyFold(organizationSlug, spec.Organizations) {
			return false
		}
	}
	return true
}

func claimMapperValue(rule ClaimMapperRule, spec ClaimMapperRuleSpec, data *HookContext, event HookEvent) (any, bool) {
	if spec.ValueFrom != "" {
		return claimMapperValueFrom(spec.ValueFrom, rule, data, event)
	}
	return claimMapperRenderTemplate(spec.Value, rule, data, event), true
}

func claimMapperValueFrom(source string, rule ClaimMapperRule, data *HookContext, event HookEvent) (any, bool) {
	source = strings.TrimSpace(strings.ToLower(source))
	switch source {
	case "mapper.id", "rule.id":
		return rule.MapperID, rule.MapperID != ""
	case "mapper.name", "rule.name":
		return rule.Name, rule.Name != ""
	case "event":
		return string(event), true
	case "client_id":
		return data.ClientID, data.ClientID != ""
	case "organization_id":
		if strings.TrimSpace(data.OrganizationID) != "" {
			return data.OrganizationID, true
		}
		return claimMapperClaimString(data.Claims, "org_id")
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
	return nil, false
}

func claimMapperRenderTemplate(template string, rule ClaimMapperRule, data *HookContext, event HookEvent) string {
	return claimMapperTemplatePattern.ReplaceAllStringFunc(template, func(raw string) string {
		matches := claimMapperTemplatePattern.FindStringSubmatch(raw)
		if len(matches) != 2 {
			return raw
		}
		value, ok := claimMapperValueFrom(strings.TrimSpace(matches[1]), rule, data, event)
		if !ok {
			return ""
		}
		return fmt.Sprint(value)
	})
}

func normalizeClaimMapperEvents(events []string) []string {
	events = normalizeClaimMapperStringList(events, true)
	if len(events) == 0 {
		return []string{string(HookBeforeTokenIssue), string(HookBeforeUserInfo)}
	}
	return events
}

func normalizeClaimMapperStringList(items []string, lower bool) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if lower {
			item = strings.ToLower(item)
		}
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func claimMapperStringsFromJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return normalizeClaimMapperStringList(values, false)
}

func mustMarshalClaimMapperStrings(values []string) string {
	values = normalizeClaimMapperStringList(values, false)
	if len(values) == 0 {
		return ""
	}
	content, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return string(content)
}

func claimMapperClaimString(claims map[string]any, key string) (string, bool) {
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

func claimMapperMatchesAnyFold(value string, candidates []string) bool {
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
