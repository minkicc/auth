/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"minki.cc/mkauth/server/config"
)

const (
	defaultEnterpriseLDAPGroupMemberAttribute = "memberOf"
	defaultEnterpriseLDAPGroupSearchFilter    = "(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))"
)

var defaultEnterpriseLDAPGroupIdentifierAttributes = []string{
	"entryUUID",
	"objectGUID",
	"gidNumber",
	"objectSid",
	"cn",
}

var defaultEnterpriseLDAPGroupNameAttributes = []string{
	"displayName",
	"cn",
	"name",
	"sAMAccountName",
	"ou",
}

type EnterpriseLDAPGroupInfo struct {
	ExternalID  string
	DisplayName string
	DN          string
}

type enterpriseLDAPCurrentGroupMembership struct {
	GroupID     string
	ExternalID  string
	DisplayName string
	RoleName    string
}

func resolveEnterpriseLDAPGroups(conn *ldap.Conn, cfg config.EnterpriseLDAPProviderConfig, entry *ldap.Entry, username string) ([]EnterpriseLDAPGroupInfo, error) {
	if conn == nil || entry == nil {
		return nil, nil
	}

	seen := map[string]EnterpriseLDAPGroupInfo{}
	addGroup := func(group EnterpriseLDAPGroupInfo) {
		group = normalizeEnterpriseLDAPGroupInfo(group)
		if group.ExternalID == "" && group.DisplayName == "" && group.DN == "" {
			return
		}
		key := strings.ToLower(firstNonEmptyString(group.ExternalID, group.DN, group.DisplayName))
		if key == "" {
			return
		}
		seen[key] = group
	}

	memberAttr := strings.TrimSpace(cfg.GroupMemberAttribute)
	if memberAttr == "" {
		memberAttr = defaultEnterpriseLDAPGroupMemberAttribute
	}
	for _, rawGroup := range entry.GetAttributeValues(memberAttr) {
		addGroup(resolveEnterpriseLDAPGroupFromMembershipValue(conn, cfg, rawGroup))
	}

	if strings.TrimSpace(cfg.GroupBaseDN) != "" || strings.TrimSpace(cfg.GroupFilter) != "" {
		searchGroups, err := searchEnterpriseLDAPGroups(conn, cfg, entry, username)
		if err != nil {
			return nil, err
		}
		for _, group := range searchGroups {
			addGroup(group)
		}
	}

	groups := make([]EnterpriseLDAPGroupInfo, 0, len(seen))
	for _, group := range seen {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		left := firstNonEmptyString(groups[i].DisplayName, groups[i].ExternalID, groups[i].DN)
		right := firstNonEmptyString(groups[j].DisplayName, groups[j].ExternalID, groups[j].DN)
		return strings.ToLower(left) < strings.ToLower(right)
	})
	return groups, nil
}

func resolveEnterpriseLDAPGroupFromMembershipValue(conn *ldap.Conn, cfg config.EnterpriseLDAPProviderConfig, raw string) EnterpriseLDAPGroupInfo {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return EnterpriseLDAPGroupInfo{}
	}
	if !enterpriseLDAPLooksLikeDN(raw) {
		return normalizeEnterpriseLDAPGroupInfo(EnterpriseLDAPGroupInfo{
			ExternalID:  raw,
			DisplayName: raw,
		})
	}

	entry, err := enterpriseLDAPEntryByDN(conn, raw, cfg.GroupIdentifierAttr, cfg.GroupNameAttribute)
	if err != nil || entry == nil {
		return normalizeEnterpriseLDAPGroupInfo(EnterpriseLDAPGroupInfo{
			ExternalID:  raw,
			DisplayName: enterpriseLDAPDisplayNameFromDN(raw),
			DN:          raw,
		})
	}
	return enterpriseLDAPGroupInfoFromEntry(cfg, entry)
}

func searchEnterpriseLDAPGroups(conn *ldap.Conn, cfg config.EnterpriseLDAPProviderConfig, entry *ldap.Entry, username string) ([]EnterpriseLDAPGroupInfo, error) {
	baseDN := strings.TrimSpace(cfg.GroupBaseDN)
	if baseDN == "" {
		baseDN = strings.TrimSpace(cfg.BaseDN)
	}
	if baseDN == "" {
		return nil, nil
	}

	filter := strings.TrimSpace(cfg.GroupFilter)
	if filter == "" {
		filter = defaultEnterpriseLDAPGroupSearchFilter
	}
	replacements := map[string]string{
		"{user_dn}":  ldap.EscapeFilter(strings.TrimSpace(entry.DN)),
		"{username}": ldap.EscapeFilter(strings.TrimSpace(username)),
	}
	for placeholder, replacement := range replacements {
		filter = strings.ReplaceAll(filter, placeholder, replacement)
	}

	searchResult, err := conn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		enterpriseLDAPGroupSearchAttributes(cfg),
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("enterprise ldap group search failed: %w", err)
	}

	groups := make([]EnterpriseLDAPGroupInfo, 0, len(searchResult.Entries))
	for _, groupEntry := range searchResult.Entries {
		group := enterpriseLDAPGroupInfoFromEntry(cfg, groupEntry)
		if group.ExternalID == "" && group.DisplayName == "" && group.DN == "" {
			continue
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func enterpriseLDAPEntryByDN(conn *ldap.Conn, dn, identifierAttr, nameAttr string) (*ldap.Entry, error) {
	searchResult, err := conn.Search(ldap.NewSearchRequest(
		strings.TrimSpace(dn),
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		enterpriseLDAPGroupSearchAttributes(config.EnterpriseLDAPProviderConfig{
			GroupIdentifierAttr: identifierAttr,
			GroupNameAttribute:  nameAttr,
		}),
		nil,
	))
	if err != nil {
		return nil, err
	}
	if len(searchResult.Entries) == 0 {
		return nil, nil
	}
	return searchResult.Entries[0], nil
}

func enterpriseLDAPGroupSearchAttributes(cfg config.EnterpriseLDAPProviderConfig) []string {
	seen := map[string]struct{}{}
	attributes := make([]string, 0, 4)
	for _, attr := range []string{
		strings.TrimSpace(cfg.GroupIdentifierAttr),
		strings.TrimSpace(cfg.GroupNameAttribute),
		"cn",
		"displayName",
	} {
		if attr == "" {
			continue
		}
		key := strings.ToLower(attr)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		attributes = append(attributes, attr)
	}
	if len(attributes) == 0 {
		return []string{"*", "+"}
	}
	return attributes
}

func enterpriseLDAPGroupInfoFromEntry(cfg config.EnterpriseLDAPProviderConfig, entry *ldap.Entry) EnterpriseLDAPGroupInfo {
	if entry == nil {
		return EnterpriseLDAPGroupInfo{}
	}
	identifier := firstEnterpriseLDAPAttribute(entry, cfg.GroupIdentifierAttr, defaultEnterpriseLDAPGroupIdentifierAttributes)
	if identifier == "" {
		identifier = strings.TrimSpace(entry.DN)
	}
	return normalizeEnterpriseLDAPGroupInfo(EnterpriseLDAPGroupInfo{
		ExternalID:  identifier,
		DisplayName: firstEnterpriseLDAPAttribute(entry, cfg.GroupNameAttribute, defaultEnterpriseLDAPGroupNameAttributes),
		DN:          strings.TrimSpace(entry.DN),
	})
}

func normalizeEnterpriseLDAPGroupInfo(group EnterpriseLDAPGroupInfo) EnterpriseLDAPGroupInfo {
	group.ExternalID = strings.TrimSpace(group.ExternalID)
	group.DisplayName = strings.TrimSpace(group.DisplayName)
	group.DN = strings.TrimSpace(group.DN)
	if group.ExternalID == "" {
		group.ExternalID = firstNonEmptyString(group.DN, group.DisplayName)
	}
	if group.DisplayName == "" {
		group.DisplayName = firstNonEmptyString(enterpriseLDAPDisplayNameFromDN(group.DN), group.ExternalID)
	}
	return group
}

func enterpriseLDAPLooksLikeDN(raw string) bool {
	return strings.Contains(raw, "=") && strings.Contains(raw, ",")
}

func enterpriseLDAPDisplayNameFromDN(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	dn, err := ldap.ParseDN(raw)
	if err == nil {
		for _, rdn := range dn.RDNs {
			for _, attribute := range rdn.Attributes {
				value := strings.TrimSpace(attribute.Value)
				if value != "" {
					return value
				}
			}
		}
	}
	if parts := strings.SplitN(raw, ",", 2); len(parts) > 0 {
		if pair := strings.SplitN(parts[0], "=", 2); len(pair) == 2 {
			return strings.TrimSpace(pair[1])
		}
	}
	return raw
}

func (m *EnterpriseLDAPManager) syncEnterpriseLDAPGroups(tx *gorm.DB, provider *EnterpriseLDAPProvider, userID string, groups []EnterpriseLDAPGroupInfo, now time.Time) error {
	if m == nil || tx == nil || provider == nil {
		return nil
	}
	organizationID := strings.TrimSpace(provider.cfg.OrganizationID)
	userID = strings.TrimSpace(userID)
	if organizationID == "" || userID == "" {
		return nil
	}

	groups = uniqueEnterpriseLDAPGroupInfos(groups)
	externalIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		externalIDs = append(externalIDs, group.ExternalID)
	}

	var existingGroups []OrganizationGroup
	if len(externalIDs) > 0 {
		if err := tx.Where("organization_id = ? AND provider_type = ? AND provider_id = ? AND external_id IN ?", organizationID, IdentityProviderTypeLDAP, provider.cfg.Slug, externalIDs).
			Find(&existingGroups).Error; err != nil {
			return err
		}
	}
	existingByExternalID := make(map[string]OrganizationGroup, len(existingGroups))
	for _, group := range existingGroups {
		existingByExternalID[strings.ToLower(group.ExternalID)] = group
	}

	currentMemberships, err := m.enterpriseLDAPCurrentUserGroupMemberships(tx, provider, userID)
	if err != nil {
		return err
	}

	desiredGroupIDs := map[string]struct{}{}
	affectedUserIDs := []string{userID}
	extraManagedRoles := []string{}

	for _, groupInfo := range groups {
		existingGroup, ok := existingByExternalID[strings.ToLower(groupInfo.ExternalID)]
		if !ok {
			groupID, err := m.service.GenerateOrganizationGroupIDWithDB(tx)
			if err != nil {
				return err
			}
			existingGroup = OrganizationGroup{
				GroupID:        groupID,
				OrganizationID: organizationID,
				ProviderType:   IdentityProviderTypeLDAP,
				ProviderID:     provider.cfg.Slug,
				ExternalID:     groupInfo.ExternalID,
				DisplayName:    groupInfo.DisplayName,
				RoleName:       enterpriseLDAPRoleNameFromDisplayName(groupInfo.DisplayName),
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			if err := tx.Create(&existingGroup).Error; err != nil {
				return err
			}
			existingByExternalID[strings.ToLower(existingGroup.ExternalID)] = existingGroup
		} else {
			nextRoleName := enterpriseLDAPRoleNameFromDisplayName(groupInfo.DisplayName)
			if existingGroup.DisplayName != groupInfo.DisplayName || existingGroup.RoleName != nextRoleName {
				memberUserIDs, err := enterpriseLDAPGroupMemberUserIDs(tx, existingGroup.GroupID)
				if err != nil {
					return err
				}
				affectedUserIDs = mergeEnterpriseLDAPStringLists(affectedUserIDs, memberUserIDs)
				if existingGroup.RoleName != nextRoleName {
					extraManagedRoles = append(extraManagedRoles, existingGroup.RoleName)
				}
				existingGroup.DisplayName = groupInfo.DisplayName
				existingGroup.RoleName = nextRoleName
				existingGroup.UpdatedAt = now
				if err := tx.Save(&existingGroup).Error; err != nil {
					return err
				}
			}
		}

		desiredGroupIDs[existingGroup.GroupID] = struct{}{}
		member := OrganizationGroupMember{
			OrganizationID: organizationID,
			GroupID:        existingGroup.GroupID,
			UserID:         userID,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "organization_id"}, {Name: "group_id"}, {Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
		}).Create(&member).Error; err != nil {
			return err
		}
	}

	for _, current := range currentMemberships {
		if _, ok := desiredGroupIDs[current.GroupID]; ok {
			continue
		}
		if err := tx.Delete(&OrganizationGroupMember{}, "organization_id = ? AND group_id = ? AND user_id = ?", organizationID, current.GroupID, userID).Error; err != nil {
			return err
		}
		extraManagedRoles = append(extraManagedRoles, current.RoleName)

		var remainingCount int64
		if err := tx.Model(&OrganizationGroupMember{}).Where("organization_id = ? AND group_id = ?", organizationID, current.GroupID).Count(&remainingCount).Error; err != nil {
			return err
		}
		if remainingCount == 0 {
			if err := tx.Delete(&OrganizationGroup{}, "group_id = ?", current.GroupID).Error; err != nil {
				return err
			}
		}
	}

	return m.recalculateEnterpriseLDAPGroupRoles(tx, provider, affectedUserIDs, extraManagedRoles, now)
}

func (m *EnterpriseLDAPManager) enterpriseLDAPCurrentUserGroupMemberships(tx *gorm.DB, provider *EnterpriseLDAPProvider, userID string) ([]enterpriseLDAPCurrentGroupMembership, error) {
	rows := []enterpriseLDAPCurrentGroupMembership{}
	if err := tx.Table("organization_groups").
		Select("organization_groups.group_id, organization_groups.external_id, organization_groups.display_name, organization_groups.role_name").
		Joins("JOIN organization_group_members ON organization_group_members.group_id = organization_groups.group_id AND organization_group_members.organization_id = organization_groups.organization_id").
		Where("organization_groups.organization_id = ? AND organization_groups.provider_type = ? AND organization_groups.provider_id = ? AND organization_group_members.user_id = ?", provider.cfg.OrganizationID, IdentityProviderTypeLDAP, provider.cfg.Slug, userID).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (m *EnterpriseLDAPManager) recalculateEnterpriseLDAPGroupRoles(tx *gorm.DB, provider *EnterpriseLDAPProvider, userIDs, extraManagedRoles []string, now time.Time) error {
	managedRoles, err := m.enterpriseLDAPManagedRoleNames(tx, provider)
	if err != nil {
		return err
	}
	managedRoleSet := map[string]struct{}{}
	for _, role := range mergeEnterpriseLDAPStringLists(managedRoles, extraManagedRoles) {
		managedRoleSet[strings.ToLower(role)] = struct{}{}
	}

	for _, userID := range uniqueEnterpriseLDAPStrings(userIDs) {
		assignedRoles, err := m.enterpriseLDAPAssignedRoleNames(tx, provider, userID)
		if err != nil {
			return err
		}
		var membership OrganizationMembership
		err = tx.First(&membership, "organization_id = ? AND user_id = ?", provider.cfg.OrganizationID, userID).Error
		switch {
		case err == nil:
			currentRoles := parseEnterpriseLDAPStringListJSON(membership.RolesJSON)
			nextRoles := make([]string, 0, len(currentRoles)+len(assignedRoles))
			for _, role := range currentRoles {
				if _, managed := managedRoleSet[strings.ToLower(role)]; managed {
					continue
				}
				nextRoles = append(nextRoles, role)
			}
			nextRoles = append(nextRoles, assignedRoles...)
			membership.RolesJSON = mustMarshalEnterpriseLDAPStringList(nextRoles)
			membership.UpdatedAt = now
			if err := tx.Save(&membership).Error; err != nil {
				return err
			}
		case err == gorm.ErrRecordNotFound:
			if len(assignedRoles) == 0 {
				continue
			}
			membership = OrganizationMembership{
				OrganizationID: provider.cfg.OrganizationID,
				UserID:         userID,
				Status:         MembershipStatusActive,
				RolesJSON:      mustMarshalEnterpriseLDAPStringList(assignedRoles),
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			if err := tx.Create(&membership).Error; err != nil {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

func (m *EnterpriseLDAPManager) enterpriseLDAPManagedRoleNames(tx *gorm.DB, provider *EnterpriseLDAPProvider) ([]string, error) {
	var roles []string
	if err := tx.Model(&OrganizationGroup{}).
		Where("organization_id = ? AND provider_type = ? AND provider_id = ?", provider.cfg.OrganizationID, IdentityProviderTypeLDAP, provider.cfg.Slug).
		Pluck("role_name", &roles).Error; err != nil {
		return nil, err
	}
	return uniqueEnterpriseLDAPStrings(roles), nil
}

func (m *EnterpriseLDAPManager) enterpriseLDAPAssignedRoleNames(tx *gorm.DB, provider *EnterpriseLDAPProvider, userID string) ([]string, error) {
	var roles []string
	if err := tx.Table("organization_groups").
		Select("organization_groups.role_name").
		Joins("JOIN organization_group_members ON organization_group_members.group_id = organization_groups.group_id AND organization_group_members.organization_id = organization_groups.organization_id").
		Where("organization_groups.organization_id = ? AND organization_groups.provider_type = ? AND organization_groups.provider_id = ? AND organization_group_members.user_id = ?", provider.cfg.OrganizationID, IdentityProviderTypeLDAP, provider.cfg.Slug, userID).
		Pluck("organization_groups.role_name", &roles).Error; err != nil {
		return nil, err
	}
	return uniqueEnterpriseLDAPStrings(roles), nil
}

func enterpriseLDAPGroupMemberUserIDs(tx *gorm.DB, groupID string) ([]string, error) {
	var userIDs []string
	if err := tx.Model(&OrganizationGroupMember{}).Where("group_id = ?", groupID).Pluck("user_id", &userIDs).Error; err != nil {
		return nil, err
	}
	return uniqueEnterpriseLDAPStrings(userIDs), nil
}

func enterpriseLDAPRoleNameFromDisplayName(displayName string) string {
	var b strings.Builder
	lastDash := false
	for _, ch := range strings.ToLower(strings.TrimSpace(displayName)) {
		valid := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == ':'
		if valid {
			b.WriteRune(ch)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	role := strings.Trim(b.String(), "-._:")
	if role == "" {
		role = "group"
	}
	if len(role) > 64 {
		role = role[:64]
	}
	return role
}

func uniqueEnterpriseLDAPGroupInfos(groups []EnterpriseLDAPGroupInfo) []EnterpriseLDAPGroupInfo {
	seen := map[string]EnterpriseLDAPGroupInfo{}
	for _, group := range groups {
		group = normalizeEnterpriseLDAPGroupInfo(group)
		key := strings.ToLower(firstNonEmptyString(group.ExternalID, group.DN, group.DisplayName))
		if key == "" {
			continue
		}
		seen[key] = group
	}
	items := make([]EnterpriseLDAPGroupInfo, 0, len(seen))
	for _, group := range seen {
		items = append(items, group)
	}
	sort.Slice(items, func(i, j int) bool {
		left := firstNonEmptyString(items[i].DisplayName, items[i].ExternalID, items[i].DN)
		right := firstNonEmptyString(items[j].DisplayName, items[j].ExternalID, items[j].DN)
		return strings.ToLower(left) < strings.ToLower(right)
	})
	return items
}

func parseEnterpriseLDAPStringListJSON(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return []string{}
	}
	return uniqueEnterpriseLDAPStrings(values)
}

func mustMarshalEnterpriseLDAPStringList(values []string) string {
	content, err := json.Marshal(uniqueEnterpriseLDAPStrings(values))
	if err != nil {
		return "[]"
	}
	return string(content)
}

func uniqueEnterpriseLDAPStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func mergeEnterpriseLDAPStringLists(left, right []string) []string {
	merged := make([]string, 0, len(left)+len(right))
	merged = append(merged, left...)
	merged = append(merged, right...)
	return uniqueEnterpriseLDAPStrings(merged)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
