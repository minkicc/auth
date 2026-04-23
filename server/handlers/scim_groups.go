package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

var scimMemberValueFilterPattern = regexp.MustCompile(`(?i)^members\[value\s+eq\s+"?([^"]+)"?\]$`)

type scimGroupRequest struct {
	Schemas     []string     `json:"schemas,omitempty"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName,omitempty"`
	Members     []scimMember `json:"members,omitempty"`
}

type scimMember struct {
	Value   string `json:"value,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

type scimGroupResource struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members,omitempty"`
	Meta        scimMeta     `json:"meta"`
}

type scimGroupListResponse struct {
	Schemas      []string            `json:"schemas"`
	TotalResults int                 `json:"totalResults"`
	StartIndex   int                 `json:"startIndex"`
	ItemsPerPage int                 `json:"itemsPerPage"`
	Resources    []scimGroupResource `json:"Resources"`
}

type scimGroupProvisionResult struct {
	Group   iam.OrganizationGroup
	Created bool
}

func (h *SCIMHandler) handleListSCIMGroups(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	startIndex, count := scimPagination(c)
	query := h.db.Model(&iam.OrganizationGroup{}).
		Where("provider_type = ? AND provider_id = ? AND organization_id = ?", iam.IdentityProviderTypeSCIM, client.Slug, client.OrganizationID)
	query = applySCIMGroupFilter(query, c.Query("filter"))

	var total int64
	if err := query.Count(&total).Error; err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	var groups []iam.OrganizationGroup
	if err := query.Order("created_at DESC").Offset(startIndex - 1).Limit(count).Find(&groups).Error; err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	resources, err := h.groupResources(c, groups)
	if err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	c.JSON(http.StatusOK, scimGroupListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: int(total),
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (h *SCIMHandler) handleCreateSCIMGroup(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	var req scimGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		scimError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM group payload")
		return
	}
	result, err := h.provisionSCIMGroup(client, req, "")
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	resource, err := h.groupResource(c, result.Group)
	if err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	c.Header("Location", resource.Meta.Location)
	status := http.StatusCreated
	if !result.Created {
		status = http.StatusOK
	}
	c.JSON(status, resource)
}

func (h *SCIMHandler) handleGetSCIMGroup(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	group, err := h.loadSCIMGroup(client, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	resource, err := h.groupResource(c, group)
	if err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	c.JSON(http.StatusOK, resource)
}

func (h *SCIMHandler) handleReplaceSCIMGroup(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	var req scimGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		scimError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM group payload")
		return
	}
	result, err := h.provisionSCIMGroup(client, req, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	resource, err := h.groupResource(c, result.Group)
	if err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	c.JSON(http.StatusOK, resource)
}

func (h *SCIMHandler) handlePatchSCIMGroup(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	group, err := h.loadSCIMGroup(client, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	resource, err := h.groupResource(c, group)
	if err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	req := scimGroupRequestFromResource(resource)
	var patch scimPatchRequest
	if err := c.ShouldBindJSON(&patch); err != nil {
		scimError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM group patch payload")
		return
	}
	if err := applySCIMGroupPatch(&req, patch); err != nil {
		scimError(c, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	result, err := h.provisionSCIMGroup(client, req, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	resource, err = h.groupResource(c, result.Group)
	if err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	c.JSON(http.StatusOK, resource)
}

func (h *SCIMHandler) handleDeleteSCIMGroup(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	group, err := h.loadSCIMGroup(client, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		affected, err := h.groupMemberUserIDs(tx, group.GroupID)
		if err != nil {
			return err
		}
		if err := tx.Delete(&iam.OrganizationGroupMember{}, "group_id = ?", group.GroupID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&iam.OrganizationGroup{}, "group_id = ?", group.GroupID).Error; err != nil {
			return err
		}
		return h.recalculateSCIMGroupRolesWithManaged(tx, client, affected, []string{group.RoleName}, time.Now())
	}); err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *SCIMHandler) provisionSCIMGroup(client config.SCIMInboundConfig, req scimGroupRequest, existingGroupID string) (scimGroupProvisionResult, error) {
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		return scimGroupProvisionResult{}, scimBadRequest("displayName is required")
	}
	externalID := strings.TrimSpace(req.ExternalID)
	if externalID == "" {
		externalID = displayName
	}
	roleName := scimRoleNameFromGroupDisplayName(displayName)
	if roleName == "" {
		return scimGroupProvisionResult{}, scimBadRequest("displayName cannot be converted to a role name")
	}
	memberIDs, err := h.resolveSCIMGroupMemberUserIDs(client, req.Members)
	if err != nil {
		return scimGroupProvisionResult{}, scimBadRequest(err.Error())
	}
	groupID, err := h.service.GenerateOrganizationGroupID()
	if err != nil {
		return scimGroupProvisionResult{}, err
	}

	var result scimGroupProvisionResult
	err = h.db.Transaction(func(tx *gorm.DB) error {
		var group iam.OrganizationGroup
		query := tx.Where("provider_type = ? AND provider_id = ? AND organization_id = ?", iam.IdentityProviderTypeSCIM, client.Slug, client.OrganizationID)
		var lookupErr error
		if strings.TrimSpace(existingGroupID) != "" {
			lookupErr = query.Where("group_id = ?", strings.TrimSpace(existingGroupID)).First(&group).Error
		} else {
			lookupErr = query.Where("external_id = ?", externalID).First(&group).Error
		}
		created := false
		var extraManagedRoles []string
		now := time.Now()
		switch {
		case lookupErr == nil:
			if group.RoleName != roleName {
				extraManagedRoles = append(extraManagedRoles, group.RoleName)
			}
			group.ExternalID = externalID
			group.DisplayName = displayName
			group.RoleName = roleName
			group.UpdatedAt = now
			if err := tx.Save(&group).Error; err != nil {
				return err
			}
		case errors.Is(lookupErr, gorm.ErrRecordNotFound) && strings.TrimSpace(existingGroupID) == "":
			created = true
			group = iam.OrganizationGroup{
				GroupID:        groupID,
				OrganizationID: client.OrganizationID,
				ProviderType:   iam.IdentityProviderTypeSCIM,
				ProviderID:     client.Slug,
				ExternalID:     externalID,
				DisplayName:    displayName,
				RoleName:       roleName,
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			if err := tx.Create(&group).Error; err != nil {
				return err
			}
		case errors.Is(lookupErr, gorm.ErrRecordNotFound):
			return gorm.ErrRecordNotFound
		default:
			return lookupErr
		}
		if err := h.replaceSCIMGroupMembers(tx, client, group, memberIDs, extraManagedRoles, now); err != nil {
			return err
		}
		result = scimGroupProvisionResult{Group: group, Created: created}
		return nil
	})
	return result, err
}

func (h *SCIMHandler) loadSCIMGroup(client config.SCIMInboundConfig, groupID string) (iam.OrganizationGroup, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return iam.OrganizationGroup{}, gorm.ErrRecordNotFound
	}
	var group iam.OrganizationGroup
	if err := h.db.First(&group, "provider_type = ? AND provider_id = ? AND organization_id = ? AND group_id = ?", iam.IdentityProviderTypeSCIM, client.Slug, client.OrganizationID, groupID).Error; err != nil {
		return iam.OrganizationGroup{}, err
	}
	return group, nil
}

func (h *SCIMHandler) groupResources(c *gin.Context, groups []iam.OrganizationGroup) ([]scimGroupResource, error) {
	resources := make([]scimGroupResource, 0, len(groups))
	for _, group := range groups {
		resource, err := h.groupResource(c, group)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func (h *SCIMHandler) groupResource(c *gin.Context, group iam.OrganizationGroup) (scimGroupResource, error) {
	members, err := h.groupMembers(group.GroupID)
	if err != nil {
		return scimGroupResource{}, err
	}
	return scimGroupResource{
		Schemas:     []string{scimGroupSchema},
		ID:          group.GroupID,
		ExternalID:  group.ExternalID,
		DisplayName: group.DisplayName,
		Members:     members,
		Meta: scimMeta{
			ResourceType: "Group",
			Created:      group.CreatedAt,
			LastModified: group.UpdatedAt,
			Location:     scimGroupLocation(c, group.GroupID),
		},
	}, nil
}

func (h *SCIMHandler) groupMembers(groupID string) ([]scimMember, error) {
	var rows []iam.OrganizationGroupMember
	if err := h.db.Where("group_id = ?", groupID).Order("user_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []scimMember{}, nil
	}
	userIDs := make([]string, 0, len(rows))
	for _, row := range rows {
		userIDs = append(userIDs, row.UserID)
	}
	usersByID := map[string]auth.User{}
	var users []auth.User
	if err := h.db.Where("user_id IN ?", userIDs).Find(&users).Error; err == nil {
		for _, user := range users {
			usersByID[user.UserID] = user
		}
	}
	members := make([]scimMember, 0, len(rows))
	for _, row := range rows {
		display := row.UserID
		if user, ok := usersByID[row.UserID]; ok {
			display = firstNonEmpty(user.Nickname, user.Username, user.UserID)
		}
		members = append(members, scimMember{Value: row.UserID, Display: display})
	}
	return members, nil
}

func scimGroupRequestFromResource(resource scimGroupResource) scimGroupRequest {
	return scimGroupRequest{
		Schemas:     resource.Schemas,
		ID:          resource.ID,
		ExternalID:  resource.ExternalID,
		DisplayName: resource.DisplayName,
		Members:     resource.Members,
	}
}

func applySCIMGroupPatch(req *scimGroupRequest, patch scimPatchRequest) error {
	for _, op := range patch.Operations {
		opName := strings.ToLower(strings.TrimSpace(op.Op))
		if opName == "" {
			opName = "replace"
		}
		path := strings.ToLower(strings.TrimSpace(op.Path))
		if path == "" {
			values, ok := op.Value.(map[string]any)
			if !ok {
				return fmt.Errorf("patch value object is required when path is empty")
			}
			applySCIMGroupPatchMap(req, opName, values)
			continue
		}
		switch opName {
		case "add":
			if path != "members" {
				return fmt.Errorf("unsupported SCIM group add path %q", op.Path)
			}
			members, err := scimMembersFromAny(op.Value)
			if err != nil {
				return err
			}
			req.Members = mergeSCIMMembers(req.Members, members)
		case "replace":
			if err := replaceSCIMGroupPath(req, path, op.Value); err != nil {
				return err
			}
		case "remove":
			if err := removeSCIMGroupPath(req, path, op.Value); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported SCIM group patch operation %q", op.Op)
		}
	}
	return nil
}

func applySCIMGroupPatchMap(req *scimGroupRequest, opName string, values map[string]any) {
	for key, value := range values {
		path := strings.ToLower(key)
		switch opName {
		case "add":
			if path == "members" {
				if members, err := scimMembersFromAny(value); err == nil {
					req.Members = mergeSCIMMembers(req.Members, members)
				}
			}
		case "replace":
			_ = replaceSCIMGroupPath(req, path, value)
		case "remove":
			_ = removeSCIMGroupPath(req, path, value)
		}
	}
}

func replaceSCIMGroupPath(req *scimGroupRequest, path string, value any) error {
	switch path {
	case "displayname":
		req.DisplayName = strings.TrimSpace(fmt.Sprint(value))
	case "externalid":
		req.ExternalID = strings.TrimSpace(fmt.Sprint(value))
	case "members":
		members, err := scimMembersFromAny(value)
		if err != nil {
			return err
		}
		req.Members = members
	default:
		return fmt.Errorf("unsupported SCIM group replace path %q", path)
	}
	return nil
}

func removeSCIMGroupPath(req *scimGroupRequest, path string, value any) error {
	if path == "members" {
		if value == nil {
			req.Members = []scimMember{}
			return nil
		}
		members, err := scimMembersFromAny(value)
		if err != nil {
			return err
		}
		req.Members = removeSCIMMembers(req.Members, members)
		return nil
	}
	if matches := scimMemberValueFilterPattern.FindStringSubmatch(path); len(matches) == 2 {
		req.Members = removeSCIMMembers(req.Members, []scimMember{{Value: matches[1]}})
		return nil
	}
	return fmt.Errorf("unsupported SCIM group remove path %q", path)
}

func scimMembersFromAny(value any) ([]scimMember, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var members []scimMember
	if err := json.Unmarshal(content, &members); err == nil {
		return normalizeSCIMMembers(members), nil
	}
	var member scimMember
	if err := json.Unmarshal(content, &member); err == nil && strings.TrimSpace(member.Value) != "" {
		return normalizeSCIMMembers([]scimMember{member}), nil
	}
	return nil, fmt.Errorf("members must be a SCIM member array")
}

func mergeSCIMMembers(existing, additions []scimMember) []scimMember {
	byValue := map[string]scimMember{}
	for _, member := range normalizeSCIMMembers(existing) {
		byValue[member.Value] = member
	}
	for _, member := range normalizeSCIMMembers(additions) {
		byValue[member.Value] = member
	}
	return sortedSCIMMembers(byValue)
}

func removeSCIMMembers(existing, removals []scimMember) []scimMember {
	byValue := map[string]scimMember{}
	for _, member := range normalizeSCIMMembers(existing) {
		byValue[member.Value] = member
	}
	for _, member := range normalizeSCIMMembers(removals) {
		delete(byValue, member.Value)
	}
	return sortedSCIMMembers(byValue)
}

func normalizeSCIMMembers(members []scimMember) []scimMember {
	byValue := map[string]scimMember{}
	for _, member := range members {
		member.Value = strings.TrimSpace(member.Value)
		member.Display = strings.TrimSpace(member.Display)
		member.Ref = strings.TrimSpace(member.Ref)
		member.Type = strings.TrimSpace(member.Type)
		if member.Value == "" {
			continue
		}
		byValue[member.Value] = member
	}
	return sortedSCIMMembers(byValue)
}

func sortedSCIMMembers(byValue map[string]scimMember) []scimMember {
	values := make([]string, 0, len(byValue))
	for value := range byValue {
		values = append(values, value)
	}
	sort.Strings(values)
	members := make([]scimMember, 0, len(values))
	for _, value := range values {
		members = append(members, byValue[value])
	}
	return members
}

func (h *SCIMHandler) resolveSCIMGroupMemberUserIDs(client config.SCIMInboundConfig, members []scimMember) ([]string, error) {
	members = normalizeSCIMMembers(members)
	if len(members) == 0 {
		return []string{}, nil
	}
	userIDs := make([]string, 0, len(members))
	for _, member := range members {
		var identity iam.ExternalIdentity
		if err := h.db.First(&identity, "provider_type = ? AND provider_id = ? AND user_id = ?", iam.IdentityProviderTypeSCIM, client.Slug, member.Value).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("member %q was not found", member.Value)
			}
			return nil, err
		}
		userIDs = append(userIDs, identity.UserID)
	}
	return userIDs, nil
}

func (h *SCIMHandler) replaceSCIMGroupMembers(tx *gorm.DB, client config.SCIMInboundConfig, group iam.OrganizationGroup, newUserIDs []string, extraManagedRoles []string, now time.Time) error {
	oldUserIDs, err := h.groupMemberUserIDs(tx, group.GroupID)
	if err != nil {
		return err
	}
	if err := tx.Delete(&iam.OrganizationGroupMember{}, "group_id = ?", group.GroupID).Error; err != nil {
		return err
	}
	for _, userID := range uniqueStrings(newUserIDs) {
		member := iam.OrganizationGroupMember{
			OrganizationID: group.OrganizationID,
			GroupID:        group.GroupID,
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
	return h.recalculateSCIMGroupRolesWithManaged(tx, client, mergeStringLists(oldUserIDs, newUserIDs), extraManagedRoles, now)
}

func (h *SCIMHandler) groupMemberUserIDs(tx *gorm.DB, groupID string) ([]string, error) {
	var userIDs []string
	if err := tx.Model(&iam.OrganizationGroupMember{}).Where("group_id = ?", groupID).Pluck("user_id", &userIDs).Error; err != nil {
		return nil, err
	}
	return uniqueStrings(userIDs), nil
}

func (h *SCIMHandler) recalculateSCIMGroupRoles(tx *gorm.DB, client config.SCIMInboundConfig, userIDs []string, now time.Time) error {
	return h.recalculateSCIMGroupRolesWithManaged(tx, client, userIDs, nil, now)
}

func (h *SCIMHandler) recalculateSCIMGroupRolesWithManaged(tx *gorm.DB, client config.SCIMInboundConfig, userIDs []string, extraManagedRoles []string, now time.Time) error {
	managedRoles, err := h.scimManagedRoleNames(tx, client)
	if err != nil {
		return err
	}
	managedRoles = mergeStringLists(managedRoles, extraManagedRoles)
	managed := stringSet(managedRoles)
	for _, userID := range uniqueStrings(userIDs) {
		assignedRoles, err := h.scimAssignedRoleNames(tx, client, userID)
		if err != nil {
			return err
		}
		var membership iam.OrganizationMembership
		err = tx.First(&membership, "organization_id = ? AND user_id = ?", client.OrganizationID, userID).Error
		switch {
		case err == nil:
			roles := parseStringListJSON(membership.RolesJSON)
			nextRoles := make([]string, 0, len(roles)+len(assignedRoles))
			for _, role := range roles {
				if _, isManaged := managed[role]; !isManaged {
					nextRoles = append(nextRoles, role)
				}
			}
			nextRoles = append(nextRoles, assignedRoles...)
			membership.RolesJSON = mustMarshalStringList(nextRoles)
			membership.UpdatedAt = now
			if err := tx.Save(&membership).Error; err != nil {
				return err
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			membership = iam.OrganizationMembership{
				OrganizationID: client.OrganizationID,
				UserID:         userID,
				Status:         iam.MembershipStatusActive,
				RolesJSON:      mustMarshalStringList(assignedRoles),
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

func (h *SCIMHandler) scimManagedRoleNames(tx *gorm.DB, client config.SCIMInboundConfig) ([]string, error) {
	var roles []string
	if err := tx.Model(&iam.OrganizationGroup{}).
		Where("provider_type = ? AND provider_id = ? AND organization_id = ?", iam.IdentityProviderTypeSCIM, client.Slug, client.OrganizationID).
		Pluck("role_name", &roles).Error; err != nil {
		return nil, err
	}
	return uniqueStrings(roles), nil
}

func (h *SCIMHandler) scimAssignedRoleNames(tx *gorm.DB, client config.SCIMInboundConfig, userID string) ([]string, error) {
	var roles []string
	if err := tx.Table("organization_groups").
		Select("organization_groups.role_name").
		Joins("JOIN organization_group_members ON organization_group_members.group_id = organization_groups.group_id").
		Where("organization_groups.provider_type = ? AND organization_groups.provider_id = ? AND organization_groups.organization_id = ? AND organization_group_members.user_id = ?", iam.IdentityProviderTypeSCIM, client.Slug, client.OrganizationID, userID).
		Pluck("organization_groups.role_name", &roles).Error; err != nil {
		return nil, err
	}
	return uniqueStrings(roles), nil
}

func applySCIMGroupFilter(query *gorm.DB, raw string) *gorm.DB {
	attr, value, ok := parseSCIMFilter(raw)
	if !ok {
		return query
	}
	switch attr {
	case "id":
		return query.Where("group_id = ?", value)
	case "externalid":
		return query.Where("external_id = ?", value)
	case "displayname":
		return query.Where("display_name = ?", value)
	default:
		return query
	}
}

func scimRoleNameFromGroupDisplayName(displayName string) string {
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
	return truncateString(role, 64)
}

func parseStringListJSON(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return []string{}
	}
	return uniqueStrings(values)
}

func mustMarshalStringList(values []string) string {
	content, err := json.Marshal(uniqueStrings(values))
	if err != nil {
		return "[]"
	}
	return string(content)
}

func uniqueStrings(values []string) []string {
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

func mergeStringLists(a, b []string) []string {
	return uniqueStrings(append(append([]string{}, a...), b...))
}

func stringSet(values []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func scimGroupLocation(c *gin.Context, groupID string) string {
	scheme := "http"
	if forwarded := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.Split(forwarded, ",")[0]
	} else if c.Request.TLS != nil {
		scheme = "https"
	}
	path := c.Request.URL.Path
	if idx := strings.Index(path, "/Groups"); idx >= 0 {
		path = path[:idx] + "/Groups/" + groupID
	}
	return fmt.Sprintf("%s://%s%s", scheme, c.Request.Host, path)
}
