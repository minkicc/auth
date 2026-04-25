package iam

import "strings"

type OrganizationAuthorizationRequirement struct {
	RequireOrganization bool
	AnyRoles            []string
	AllRoles            []string
	AnyGroups           []string
	AllGroups           []string
	AnyPermissions      []string
	AllPermissions      []string
}

func (r OrganizationAuthorizationRequirement) Normalize() OrganizationAuthorizationRequirement {
	r.AnyRoles = normalizeAuthorizationRequirementValues(r.AnyRoles)
	r.AllRoles = normalizeAuthorizationRequirementValues(r.AllRoles)
	r.AnyGroups = normalizeAuthorizationRequirementValues(r.AnyGroups)
	r.AllGroups = normalizeAuthorizationRequirementValues(r.AllGroups)
	r.AnyPermissions = normalizeAuthorizationRequirementValues(r.AnyPermissions)
	r.AllPermissions = normalizeAuthorizationRequirementValues(r.AllPermissions)
	return r
}

func (r OrganizationAuthorizationRequirement) Configured() bool {
	r = r.Normalize()
	return r.RequireOrganization ||
		len(r.AnyRoles) > 0 ||
		len(r.AllRoles) > 0 ||
		len(r.AnyGroups) > 0 ||
		len(r.AllGroups) > 0 ||
		len(r.AnyPermissions) > 0 ||
		len(r.AllPermissions) > 0
}

func OrganizationAuthorizationMatches(authz OrganizationAuthorization, requirement OrganizationAuthorizationRequirement) bool {
	requirement = requirement.Normalize()
	if requirement.RequireOrganization && strings.TrimSpace(authz.OrganizationID) == "" {
		return false
	}
	if len(requirement.AnyRoles) > 0 && !authorizationAnyMatch(authz.RoleSlugs, requirement.AnyRoles) {
		return false
	}
	if len(requirement.AllRoles) > 0 && !authorizationAllMatch(authz.RoleSlugs, requirement.AllRoles) {
		return false
	}
	if len(requirement.AnyGroups) > 0 && !authorizationAnyMatch(authz.GroupNames, requirement.AnyGroups) {
		return false
	}
	if len(requirement.AllGroups) > 0 && !authorizationAllMatch(authz.GroupNames, requirement.AllGroups) {
		return false
	}
	if len(requirement.AnyPermissions) > 0 && !authorizationAnyMatch(authz.PermissionKeys, requirement.AnyPermissions) {
		return false
	}
	if len(requirement.AllPermissions) > 0 && !authorizationAllMatch(authz.PermissionKeys, requirement.AllPermissions) {
		return false
	}
	return true
}

func normalizeAuthorizationRequirementValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func authorizationAnyMatch(values, required []string) bool {
	requiredSet := make(map[string]struct{}, len(required))
	for _, item := range normalizeAuthorizationRequirementValues(required) {
		requiredSet[item] = struct{}{}
	}
	if len(requiredSet) == 0 {
		return true
	}
	for _, value := range normalizeAuthorizationRequirementValues(values) {
		if _, ok := requiredSet[value]; ok {
			return true
		}
	}
	return false
}

func authorizationAllMatch(values, required []string) bool {
	requiredSet := make(map[string]struct{}, len(required))
	for _, item := range normalizeAuthorizationRequirementValues(required) {
		requiredSet[item] = struct{}{}
	}
	if len(requiredSet) == 0 {
		return true
	}
	valueSet := make(map[string]struct{}, len(values))
	for _, value := range normalizeAuthorizationRequirementValues(values) {
		valueSet[value] = struct{}{}
	}
	for item := range requiredSet {
		if _, ok := valueSet[item]; !ok {
			return false
		}
	}
	return true
}
