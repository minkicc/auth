package iam

import (
	"encoding/json"
	"sort"
	"strings"

	"gorm.io/gorm"
)

type OrganizationAuthorization struct {
	OrganizationID string
	RoleSlugs      []string
	PermissionKeys []string
	GroupNames     []string
}

type organizationRoleBindingCandidate struct {
	RoleID string
}

type organizationGroupAssignment struct {
	GroupID     string
	DisplayName string
	LegacyRole  string
}

func (s *Service) ResolveOrganizationAuthorization(userID, organizationID string) (OrganizationAuthorization, error) {
	if s == nil || s.db == nil || strings.TrimSpace(userID) == "" || strings.TrimSpace(organizationID) == "" {
		return OrganizationAuthorization{}, gorm.ErrRecordNotFound
	}

	var membership OrganizationMembership
	if err := s.db.
		Where("organization_id = ? AND user_id = ? AND status = ?", strings.TrimSpace(organizationID), strings.TrimSpace(userID), MembershipStatusActive).
		First(&membership).Error; err != nil {
		return OrganizationAuthorization{}, err
	}

	result := OrganizationAuthorization{
		OrganizationID: membership.OrganizationID,
		RoleSlugs:      parseOrganizationAuthorizationStringList(membership.RolesJSON),
	}

	groupAssignments, err := s.organizationGroupAssignments(userID, membership.OrganizationID)
	if err != nil {
		return OrganizationAuthorization{}, err
	}
	groupIDs := make([]string, 0, len(groupAssignments))
	for _, assignment := range groupAssignments {
		groupIDs = append(groupIDs, assignment.GroupID)
		result.GroupNames = append(result.GroupNames, assignment.DisplayName)
		if role := strings.TrimSpace(assignment.LegacyRole); role != "" {
			result.RoleSlugs = append(result.RoleSlugs, role)
		}
	}

	rolesByID, rolesBySlug, err := s.organizationRoles(membership.OrganizationID)
	if err != nil {
		return OrganizationAuthorization{}, err
	}

	boundRoleIDs, err := s.organizationBoundRoleIDs(membership.OrganizationID, userID, groupIDs)
	if err != nil {
		return OrganizationAuthorization{}, err
	}
	for _, roleID := range boundRoleIDs {
		if role, ok := rolesByID[roleID]; ok && role.Enabled {
			result.RoleSlugs = append(result.RoleSlugs, role.Slug)
		}
	}

	filteredRoleSlugs := make([]string, 0, len(result.RoleSlugs))
	for _, slug := range result.RoleSlugs {
		if role, ok := rolesBySlug[strings.ToLower(slug)]; ok && !role.Enabled {
			continue
		}
		filteredRoleSlugs = append(filteredRoleSlugs, slug)
	}
	result.RoleSlugs = uniqueSortedAuthorizationStrings(filteredRoleSlugs)
	result.GroupNames = uniqueSortedAuthorizationStrings(result.GroupNames)

	permissionRoleIDs := make([]string, 0, len(result.RoleSlugs))
	for _, slug := range result.RoleSlugs {
		if role, ok := rolesBySlug[strings.ToLower(slug)]; ok {
			permissionRoleIDs = append(permissionRoleIDs, role.RoleID)
		}
	}
	result.PermissionKeys, err = s.organizationPermissionKeys(membership.OrganizationID, permissionRoleIDs)
	if err != nil {
		return OrganizationAuthorization{}, err
	}

	return result, nil
}

func (s *Service) organizationGroupAssignments(userID, organizationID string) ([]organizationGroupAssignment, error) {
	if s.db == nil || !s.db.Migrator().HasTable(&OrganizationGroup{}) || !s.db.Migrator().HasTable(&OrganizationGroupMember{}) {
		return nil, nil
	}

	var rows []organizationGroupAssignment
	if err := s.db.Table("organization_groups").
		Select("organization_groups.group_id, organization_groups.display_name, organization_groups.role_name AS legacy_role").
		Joins("JOIN organization_group_members ON organization_group_members.group_id = organization_groups.group_id AND organization_group_members.organization_id = organization_groups.organization_id").
		Where("organization_groups.organization_id = ? AND organization_group_members.user_id = ?", organizationID, userID).
		Order("organization_groups.display_name ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *Service) organizationRoles(organizationID string) (map[string]OrganizationRole, map[string]OrganizationRole, error) {
	if s.db == nil || !s.db.Migrator().HasTable(&OrganizationRole{}) {
		return map[string]OrganizationRole{}, map[string]OrganizationRole{}, nil
	}

	var rows []OrganizationRole
	if err := s.db.Where("organization_id = ?", organizationID).Find(&rows).Error; err != nil {
		return nil, nil, err
	}

	byID := make(map[string]OrganizationRole, len(rows))
	bySlug := make(map[string]OrganizationRole, len(rows))
	for _, role := range rows {
		byID[role.RoleID] = role
		bySlug[strings.ToLower(strings.TrimSpace(role.Slug))] = role
	}
	return byID, bySlug, nil
}

func (s *Service) organizationBoundRoleIDs(organizationID, userID string, groupIDs []string) ([]string, error) {
	if s.db == nil || !s.db.Migrator().HasTable(&OrganizationRoleBinding{}) {
		return nil, nil
	}

	roleIDs := make([]string, 0)

	var directRows []organizationRoleBindingCandidate
	if err := s.db.Model(&OrganizationRoleBinding{}).
		Select("role_id").
		Where("organization_id = ? AND subject_type = ? AND subject_id = ?", organizationID, RoleBindingSubjectMembership, userID).
		Scan(&directRows).Error; err != nil {
		return nil, err
	}
	for _, row := range directRows {
		roleIDs = append(roleIDs, row.RoleID)
	}

	groupIDs = uniqueSortedAuthorizationStrings(groupIDs)
	if len(groupIDs) > 0 {
		var groupRows []organizationRoleBindingCandidate
		if err := s.db.Model(&OrganizationRoleBinding{}).
			Select("role_id").
			Where("organization_id = ? AND subject_type = ? AND subject_id IN ?", organizationID, RoleBindingSubjectGroup, groupIDs).
			Scan(&groupRows).Error; err != nil {
			return nil, err
		}
		for _, row := range groupRows {
			roleIDs = append(roleIDs, row.RoleID)
		}
	}

	return uniqueSortedAuthorizationStrings(roleIDs), nil
}

func (s *Service) organizationPermissionKeys(organizationID string, roleIDs []string) ([]string, error) {
	if s.db == nil || len(roleIDs) == 0 || !s.db.Migrator().HasTable(&OrganizationRolePermission{}) {
		return nil, nil
	}

	var rows []OrganizationRolePermission
	if err := s.db.Where("organization_id = ? AND role_id IN ?", organizationID, uniqueSortedAuthorizationStrings(roleIDs)).Find(&rows).Error; err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, row.PermissionKey)
	}
	return uniqueSortedAuthorizationStrings(keys), nil
}

func parseOrganizationAuthorizationStringList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return uniqueSortedAuthorizationStrings(values)
}

func uniqueSortedAuthorizationStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]string, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; !ok {
			seen[key] = trimmed
		}
	}
	if len(seen) == 0 {
		return nil
	}

	result := make([]string, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
