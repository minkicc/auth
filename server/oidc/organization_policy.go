/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package oidc

import (
	"errors"
	"sort"
	"strings"

	"gorm.io/gorm"

	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

var ErrClientNotFound = errors.New("oidc client not found")

func (p *Provider) clientUsesOrganizationPolicy(client config.OIDCClientConfig, requestedScopes []string) bool {
	return len(p.organizationPoliciesForScopes(client, requestedScopes)) > 0
}

func (p *Provider) AuthorizedOrganizationIDsForClient(userID, clientID, scope string) (map[string]struct{}, bool, error) {
	client, ok := p.findClient(strings.TrimSpace(clientID))
	if !ok {
		return nil, false, ErrClientNotFound
	}
	requestedScopes := normalizeRequestedScopes(strings.Fields(scope))
	if !p.clientUsesOrganizationPolicy(client, requestedScopes) {
		return nil, false, nil
	}

	organizations, err := p.listAuthorizedOrganizations(userID, client, requestedScopes)
	if err != nil {
		return nil, true, err
	}
	allowed := make(map[string]struct{}, len(organizations))
	for _, organization := range organizations {
		allowed[organization.OrgID] = struct{}{}
	}
	return allowed, true, nil
}

func (p *Provider) listAuthorizedOrganizations(userID string, client config.OIDCClientConfig, requestedScopes []string) ([]organizationClaims, error) {
	if p.db == nil || userID == "" || !p.db.Migrator().HasTable(&iam.OrganizationMembership{}) {
		return nil, nil
	}

	var memberships []iam.OrganizationMembership
	if err := p.db.Where("user_id = ? AND status = ?", userID, iam.MembershipStatusActive).
		Order("created_at ASC").
		Find(&memberships).Error; err != nil {
		return nil, err
	}
	if len(memberships) == 0 {
		return nil, nil
	}

	orgIDs := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		orgIDs = append(orgIDs, membership.OrganizationID)
	}

	orgMap, err := p.organizationMapByID(orgIDs)
	if err != nil {
		return nil, err
	}
	claimsList := make([]organizationClaims, 0, len(memberships))
	for _, membership := range memberships {
		claims := organizationClaims{OrgID: membership.OrganizationID}
		if organization, ok := orgMap[membership.OrganizationID]; ok {
			if organization.Status != iam.OrganizationStatusActive {
				continue
			}
			claims.OrgSlug = organization.Slug
		}
		authz, err := iam.NewService(p.db).ResolveOrganizationAuthorization(userID, membership.OrganizationID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		if err == nil {
			claims.OrgRoles = authz.RoleSlugs
			claims.OrgGroups = authz.GroupNames
		}
		if p.organizationAllowedForClient(client, claims, requestedScopes) {
			claimsList = append(claimsList, claims)
		}
	}
	return claimsList, nil
}

func (p *Provider) organizationAllowedForClient(client config.OIDCClientConfig, claims organizationClaims, requestedScopes []string) bool {
	policies := p.organizationPoliciesForScopes(client, requestedScopes)
	if len(policies) == 0 {
		return claims.OrgID != ""
	}
	if claims.OrgID == "" {
		return false
	}
	for _, policy := range policies {
		if !organizationAllowedForPolicy(policy, claims) {
			return false
		}
	}
	return true
}

func organizationAllowedForPolicy(policy config.OIDCOrganizationPolicy, claims organizationClaims) bool {
	if len(policy.AllowedOrganizations) > 0 {
		matched := false
		for _, allowed := range policy.AllowedOrganizations {
			allowed = strings.TrimSpace(allowed)
			if allowed == "" {
				continue
			}
			if strings.EqualFold(allowed, claims.OrgID) || strings.EqualFold(allowed, claims.OrgSlug) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(policy.RequiredOrgRoles) > 0 && !anyStringMatchFold(claims.OrgRoles, policy.RequiredOrgRoles) {
		return false
	}
	if len(policy.RequiredOrgRolesAll) > 0 && !allStringMatchFold(claims.OrgRoles, policy.RequiredOrgRolesAll) {
		return false
	}
	if len(policy.RequiredOrgGroups) > 0 && !anyStringMatchFold(claims.OrgGroups, policy.RequiredOrgGroups) {
		return false
	}
	if len(policy.RequiredOrgGroupsAll) > 0 && !allStringMatchFold(claims.OrgGroups, policy.RequiredOrgGroupsAll) {
		return false
	}
	if policy.RequireOrganization && claims.OrgID == "" {
		return false
	}
	return true
}

func (p *Provider) organizationPoliciesForScopes(client config.OIDCClientConfig, requestedScopes []string) []config.OIDCOrganizationPolicy {
	policies := make([]config.OIDCOrganizationPolicy, 0, 1+len(requestedScopes))
	basePolicy := normalizeOrganizationPolicy(client.OIDCOrganizationPolicy)
	if organizationPolicyConfigured(basePolicy) {
		policies = append(policies, basePolicy)
	}
	if len(client.ScopePolicies) == 0 || len(requestedScopes) == 0 {
		return policies
	}
	seen := make(map[string]struct{}, len(requestedScopes))
	for _, scope := range normalizeRequestedScopes(requestedScopes) {
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		policy, ok := client.ScopePolicies[scope]
		if !ok {
			continue
		}
		policy = normalizeOrganizationPolicy(policy)
		if organizationPolicyConfigured(policy) {
			policies = append(policies, policy)
		}
	}
	return policies
}

func (p *Provider) organizationMapByID(organizationIDs []string) (map[string]iam.Organization, error) {
	result := map[string]iam.Organization{}
	if p.db == nil || len(organizationIDs) == 0 || !p.db.Migrator().HasTable(&iam.Organization{}) {
		return result, nil
	}

	var organizations []iam.Organization
	if err := p.db.Where("organization_id IN ?", uniqueSortedStrings(organizationIDs)).Find(&organizations).Error; err != nil {
		return nil, err
	}
	for _, organization := range organizations {
		result[organization.OrganizationID] = organization
	}
	return result, nil
}

func (p *Provider) organizationGroupDisplayNamesForUser(userID string, organizationIDs []string) (map[string][]string, error) {
	result := map[string][]string{}
	if p.db == nil || userID == "" || len(organizationIDs) == 0 || !p.db.Migrator().HasTable(&iam.OrganizationGroup{}) || !p.db.Migrator().HasTable(&iam.OrganizationGroupMember{}) {
		return result, nil
	}

	var rows []struct {
		OrganizationID string
		DisplayName    string
	}
	if err := p.db.Table("organization_groups").
		Select("organization_groups.organization_id, organization_groups.display_name").
		Joins("JOIN organization_group_members ON organization_group_members.group_id = organization_groups.group_id AND organization_group_members.organization_id = organization_groups.organization_id").
		Where("organization_group_members.user_id = ? AND organization_groups.organization_id IN ?", userID, uniqueSortedStrings(organizationIDs)).
		Order("organization_groups.display_name ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	for _, row := range rows {
		result[row.OrganizationID] = append(result[row.OrganizationID], row.DisplayName)
	}
	for organizationID, groups := range result {
		result[organizationID] = uniqueSortedStrings(groups)
	}
	return result, nil
}

func organizationClaimsMatchHint(claims organizationClaims, hint string) bool {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return false
	}
	return strings.EqualFold(hint, claims.OrgID) || strings.EqualFold(hint, claims.OrgSlug)
}

func anyStringMatchFold(values, required []string) bool {
	requiredSet := map[string]struct{}{}
	for _, item := range required {
		item = strings.TrimSpace(strings.ToLower(item))
		if item != "" {
			requiredSet[item] = struct{}{}
		}
	}
	if len(requiredSet) == 0 {
		return true
	}
	for _, value := range values {
		if _, ok := requiredSet[strings.ToLower(strings.TrimSpace(value))]; ok {
			return true
		}
	}
	return false
}

func allStringMatchFold(values, required []string) bool {
	requiredSet := map[string]struct{}{}
	for _, item := range required {
		item = strings.TrimSpace(strings.ToLower(item))
		if item != "" {
			requiredSet[item] = struct{}{}
		}
	}
	if len(requiredSet) == 0 {
		return true
	}
	valueSet := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value != "" {
			valueSet[value] = struct{}{}
		}
	}
	for item := range requiredSet {
		if _, ok := valueSet[item]; !ok {
			return false
		}
	}
	return true
}

func normalizeRequestedScopes(requestedScopes []string) []string {
	if len(requestedScopes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(requestedScopes))
	normalized := make([]string, 0, len(requestedScopes))
	for _, scope := range requestedScopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	sort.Strings(normalized)
	return normalized
}
