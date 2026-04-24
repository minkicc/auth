package admin

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
	"minki.cc/mkauth/server/iam"
)

var (
	organizationSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,78}[a-z0-9]$|^[a-z0-9]$`)
	roleNamePattern         = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

type organizationPayload struct {
	Slug        string         `json:"slug"`
	Name        string         `json:"name"`
	DisplayName string         `json:"display_name"`
	Status      string         `json:"status"`
	Metadata    map[string]any `json:"metadata"`
}

type domainPayload struct {
	Domain   string `json:"domain"`
	Verified bool   `json:"verified"`
}

type membershipPayload struct {
	UserID string   `json:"user_id"`
	Status string   `json:"status"`
	Roles  []string `json:"roles"`
}

type organizationGroupPayload struct {
	DisplayName string   `json:"display_name"`
	RoleName    string   `json:"role_name"`
	UserIDs     []string `json:"user_ids"`
}

type organizationMembershipView struct {
	OrganizationID string    `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Status         string    `json:"status"`
	Roles          []string  `json:"roles"`
	Username       string    `json:"username,omitempty"`
	Nickname       string    `json:"nickname,omitempty"`
	Avatar         string    `json:"avatar,omitempty"`
	UserStatus     string    `json:"user_status,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type organizationGroupMemberView struct {
	UserID     string `json:"user_id"`
	Username   string `json:"username,omitempty"`
	Nickname   string `json:"nickname,omitempty"`
	Avatar     string `json:"avatar,omitempty"`
	UserStatus string `json:"user_status,omitempty"`
}

type organizationGroupView struct {
	GroupID        string                        `json:"group_id"`
	OrganizationID string                        `json:"organization_id"`
	ProviderType   string                        `json:"provider_type"`
	ProviderID     string                        `json:"provider_id,omitempty"`
	ExternalID     string                        `json:"external_id,omitempty"`
	DisplayName    string                        `json:"display_name"`
	RoleName       string                        `json:"role_name"`
	Editable       bool                          `json:"editable"`
	MemberCount    int                           `json:"member_count"`
	Members        []organizationGroupMemberView `json:"members,omitempty"`
	CreatedAt      time.Time                     `json:"created_at"`
	UpdatedAt      time.Time                     `json:"updated_at"`
}

func (s *AdminServer) handleListOrganizations(c *gin.Context) {
	page, pageSize := adminPagination(c, 20, 100)
	query := s.db.Model(&iam.Organization{})
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		like := "%" + search + "%"
		query = query.Where("slug LIKE ? OR name LIKE ? OR display_name LIKE ?", like, like, like)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var organizations []iam.Organization
	if err := query.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&organizations).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"organizations": organizations,
		"total":         total,
		"page":          page,
		"page_size":     pageSize,
	})
}

func (s *AdminServer) handleCreateOrganization(c *gin.Context) {
	var req organizationPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization payload"})
		return
	}
	org, err := s.organizationFromPayload(req, nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	orgID, err := iam.NewService(s.db).GenerateOrganizationID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	org.OrganizationID = orgID
	if err := s.db.Create(&org).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"organization": org})
}

func (s *AdminServer) handleGetOrganization(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"organization": org})
}

func (s *AdminServer) handleUpdateOrganization(c *gin.Context) {
	current, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var req organizationPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization payload"})
		return
	}
	updated, err := s.organizationFromPayload(req, &current)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Save(&updated).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"organization": updated})
}

func (s *AdminServer) handleListOrganizationDomains(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var domains []iam.OrganizationDomain
	if err := s.db.Where("organization_id = ?", org.OrganizationID).Order("domain ASC").Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"domains": domains})
}

func (s *AdminServer) handleCreateOrganizationDomain(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var req domainPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain payload"})
		return
	}
	domain, err := normalizeOrganizationDomain(req.Domain)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	record := iam.OrganizationDomain{
		Domain:         domain,
		OrganizationID: org.OrganizationID,
		Verified:       req.Verified,
	}
	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "domain"}},
		DoUpdates: clause.AssignmentColumns([]string{"organization_id", "verified", "updated_at"}),
	}).Create(&record).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"domain": record})
}

func (s *AdminServer) handleUpdateOrganizationDomain(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	domain, err := normalizeOrganizationDomain(c.Param("domain"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req domainPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain payload"})
		return
	}
	var record iam.OrganizationDomain
	if err := s.db.First(&record, "domain = ? AND organization_id = ?", domain, org.OrganizationID).Error; err != nil {
		writeNotFoundOrError(c, err, "organization domain was not found")
		return
	}
	record.Verified = req.Verified
	if err := s.db.Save(&record).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"domain": record})
}

func (s *AdminServer) handleDeleteOrganizationDomain(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	domain, err := normalizeOrganizationDomain(c.Param("domain"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Delete(&iam.OrganizationDomain{}, "domain = ? AND organization_id = ?", domain, org.OrganizationID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "organization domain deleted successfully"})
}

func (s *AdminServer) handleListOrganizationMemberships(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var memberships []iam.OrganizationMembership
	if err := s.db.Where("organization_id = ?", org.OrganizationID).Order("created_at DESC").Find(&memberships).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"memberships": s.membershipViews(memberships)})
}

func (s *AdminServer) handleUpsertOrganizationMembership(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var req membershipPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid membership payload"})
		return
	}
	req.UserID = strings.TrimSpace(req.UserID)
	if req.UserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}
	user, ok := s.loadAdminUser(req.UserID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user was not found"})
		return
	}
	status, err := normalizeMembershipStatus(req.Status)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	roles, rolesJSON, err := normalizeRoleList(req.Roles)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	now := time.Now()
	membership := iam.OrganizationMembership{
		OrganizationID: org.OrganizationID,
		UserID:         req.UserID,
		Status:         status,
		RolesJSON:      rolesJSON,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "organization_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "roles_json", "updated_at"}),
	}).Create(&membership).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"membership": s.membershipView(membership, roles, user)})
}

func (s *AdminServer) handleUpdateOrganizationMembership(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	userID := strings.TrimSpace(c.Param("user_id"))
	var membership iam.OrganizationMembership
	if err := s.db.First(&membership, "organization_id = ? AND user_id = ?", org.OrganizationID, userID).Error; err != nil {
		writeNotFoundOrError(c, err, "organization membership was not found")
		return
	}
	var req membershipPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid membership payload"})
		return
	}
	status, err := normalizeMembershipStatus(req.Status)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	roles, rolesJSON, err := normalizeRoleList(req.Roles)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	membership.Status = status
	membership.RolesJSON = rolesJSON
	if err := s.db.Save(&membership).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user, _ := s.loadAdminUser(membership.UserID)
	c.JSON(http.StatusOK, gin.H{"membership": s.membershipView(membership, roles, user)})
}

func (s *AdminServer) handleDeleteOrganizationMembership(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	userID := strings.TrimSpace(c.Param("user_id"))
	if err := s.db.Delete(&iam.OrganizationMembership{}, "organization_id = ? AND user_id = ?", org.OrganizationID, userID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "organization membership deleted successfully"})
}

func (s *AdminServer) handleListOrganizationGroups(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var groups []iam.OrganizationGroup
	if err := s.db.Where("organization_id = ?", org.OrganizationID).Order("created_at DESC").Find(&groups).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	views, err := s.organizationGroupViews(groups, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"groups": views})
}

func (s *AdminServer) handleGetOrganizationGroup(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	group, ok := s.loadOrganizationGroup(c, org.OrganizationID, c.Param("group_id"))
	if !ok {
		return
	}
	view, err := s.organizationGroupView(group, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"group": view})
}

func (s *AdminServer) handleCreateOrganizationGroup(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	var req organizationGroupPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization group payload"})
		return
	}
	displayName, roleName, userIDs, users, err := s.normalizeOrganizationGroupPayload(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	service := iam.NewService(s.db)
	groupID, err := service.GenerateOrganizationGroupID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	now := time.Now()
	group := iam.OrganizationGroup{
		GroupID:        groupID,
		OrganizationID: org.OrganizationID,
		ProviderType:   iam.IdentityProviderTypeManual,
		ProviderID:     iam.ManualOrganizationGroupProvider,
		ExternalID:     groupID,
		DisplayName:    displayName,
		RoleName:       roleName,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&group).Error; err != nil {
			return err
		}
		if err := s.replaceOrganizationGroupMembers(tx, org.OrganizationID, group.GroupID, userIDs, now); err != nil {
			return err
		}
		return s.reconcileManualOrganizationGroupRoles(tx, org.OrganizationID, userIDs, nil, now)
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"group": s.organizationGroupViewWithUsers(group, users, len(userIDs), true)})
}

func (s *AdminServer) handleUpdateOrganizationGroup(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	group, ok := s.loadOrganizationGroup(c, org.OrganizationID, c.Param("group_id"))
	if !ok {
		return
	}
	if group.ProviderType != iam.IdentityProviderTypeManual {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only manual organization groups can be updated"})
		return
	}
	var req organizationGroupPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization group payload"})
		return
	}
	displayName, roleName, userIDs, users, err := s.normalizeOrganizationGroupPayload(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var updated iam.OrganizationGroup
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		existingUserIDs, err := s.groupMemberUserIDs(tx, group.GroupID)
		if err != nil {
			return err
		}
		previousRoleName := group.RoleName
		group.DisplayName = displayName
		group.RoleName = roleName
		group.UpdatedAt = time.Now()
		if err := tx.Save(&group).Error; err != nil {
			return err
		}
		if err := s.replaceOrganizationGroupMembers(tx, org.OrganizationID, group.GroupID, userIDs, group.UpdatedAt); err != nil {
			return err
		}
		if err := s.reconcileManualOrganizationGroupRoles(tx, org.OrganizationID, mergeUniqueStrings(existingUserIDs, userIDs), []string{previousRoleName}, group.UpdatedAt); err != nil {
			return err
		}
		updated = group
		return nil
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"group": s.organizationGroupViewWithUsers(updated, users, len(userIDs), true)})
}

func (s *AdminServer) handleDeleteOrganizationGroup(c *gin.Context) {
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	group, ok := s.loadOrganizationGroup(c, org.OrganizationID, c.Param("group_id"))
	if !ok {
		return
	}
	if group.ProviderType != iam.IdentityProviderTypeManual {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only manual organization groups can be deleted"})
		return
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		userIDs, err := s.groupMemberUserIDs(tx, group.GroupID)
		if err != nil {
			return err
		}
		if err := tx.Delete(&iam.OrganizationGroupMember{}, "group_id = ?", group.GroupID).Error; err != nil {
			return err
		}
		if err := tx.Delete(&iam.OrganizationGroup{}, "group_id = ?", group.GroupID).Error; err != nil {
			return err
		}
		return s.reconcileManualOrganizationGroupRoles(tx, org.OrganizationID, userIDs, []string{group.RoleName}, time.Now())
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "organization group deleted successfully"})
}

func (s *AdminServer) organizationFromPayload(req organizationPayload, current *iam.Organization) (iam.Organization, error) {
	slug := strings.TrimSpace(strings.ToLower(req.Slug))
	name := strings.TrimSpace(req.Name)
	status, err := normalizeOrganizationStatus(req.Status)
	if err != nil {
		return iam.Organization{}, err
	}
	if !organizationSlugPattern.MatchString(slug) {
		return iam.Organization{}, fmt.Errorf("slug must use lowercase letters, numbers, and hyphens")
	}
	if name == "" {
		return iam.Organization{}, fmt.Errorf("name is required")
	}
	metadataJSON, err := marshalMetadata(req.Metadata)
	if err != nil {
		return iam.Organization{}, err
	}
	if current != nil {
		current.Slug = slug
		current.Name = name
		current.DisplayName = strings.TrimSpace(req.DisplayName)
		current.Status = status
		current.MetadataJSON = metadataJSON
		return *current, nil
	}
	return iam.Organization{
		Slug:         slug,
		Name:         name,
		DisplayName:  strings.TrimSpace(req.DisplayName),
		Status:       status,
		MetadataJSON: metadataJSON,
	}, nil
}

func (s *AdminServer) loadOrganization(c *gin.Context, idOrSlug string) (iam.Organization, bool) {
	idOrSlug = strings.TrimSpace(idOrSlug)
	var org iam.Organization
	err := s.db.First(&org, "organization_id = ? OR slug = ?", idOrSlug, strings.ToLower(idOrSlug)).Error
	if err != nil {
		writeNotFoundOrError(c, err, "organization was not found")
		return iam.Organization{}, false
	}
	return org, true
}

func (s *AdminServer) loadAdminUser(userID string) (*auth.User, bool) {
	var user auth.User
	if err := s.db.First(&user, "user_id = ?", userID).Error; err != nil {
		return nil, false
	}
	return &user, true
}

func (s *AdminServer) membershipViews(items []iam.OrganizationMembership) []organizationMembershipView {
	if len(items) == 0 {
		return []organizationMembershipView{}
	}
	userIDs := make([]string, 0, len(items))
	for _, item := range items {
		userIDs = append(userIDs, item.UserID)
	}
	users := map[string]auth.User{}
	var userRows []auth.User
	if err := s.db.Where("user_id IN ?", userIDs).Find(&userRows).Error; err == nil {
		for _, user := range userRows {
			users[user.UserID] = user
		}
	}
	views := make([]organizationMembershipView, 0, len(items))
	for _, item := range items {
		user, ok := users[item.UserID]
		var userPtr *auth.User
		if ok {
			userCopy := user
			userPtr = &userCopy
		}
		views = append(views, s.membershipView(item, nil, userPtr))
	}
	return views
}

func (s *AdminServer) membershipView(item iam.OrganizationMembership, roles []string, user *auth.User) organizationMembershipView {
	if roles == nil {
		roles = parseRolesJSON(item.RolesJSON)
	}
	view := organizationMembershipView{
		OrganizationID: item.OrganizationID,
		UserID:         item.UserID,
		Status:         string(item.Status),
		Roles:          roles,
		CreatedAt:      item.CreatedAt,
		UpdatedAt:      item.UpdatedAt,
	}
	if user != nil {
		view.Username = user.Username
		view.Nickname = user.Nickname
		view.Avatar = user.Avatar
		view.UserStatus = string(user.Status)
	}
	return view
}

func (s *AdminServer) loadOrganizationGroup(c *gin.Context, organizationID, groupID string) (iam.OrganizationGroup, bool) {
	groupID = strings.TrimSpace(groupID)
	var group iam.OrganizationGroup
	if err := s.db.First(&group, "organization_id = ? AND group_id = ?", organizationID, groupID).Error; err != nil {
		writeNotFoundOrError(c, err, "organization group was not found")
		return iam.OrganizationGroup{}, false
	}
	return group, true
}

func (s *AdminServer) organizationGroupViews(groups []iam.OrganizationGroup, includeMembers bool) ([]organizationGroupView, error) {
	if len(groups) == 0 {
		return []organizationGroupView{}, nil
	}
	groupIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		groupIDs = append(groupIDs, group.GroupID)
	}
	var memberRows []iam.OrganizationGroupMember
	if err := s.db.Where("group_id IN ?", groupIDs).Find(&memberRows).Error; err != nil {
		return nil, err
	}
	memberMap := map[string][]string{}
	memberCount := map[string]int{}
	userIDSet := map[string]struct{}{}
	for _, member := range memberRows {
		memberMap[member.GroupID] = append(memberMap[member.GroupID], member.UserID)
		memberCount[member.GroupID]++
		userIDSet[member.UserID] = struct{}{}
	}
	users, err := s.loadAdminUsersMap(stringKeys(userIDSet))
	if err != nil {
		return nil, err
	}
	views := make([]organizationGroupView, 0, len(groups))
	for _, group := range groups {
		memberUsers := usersForIDs(users, memberMap[group.GroupID])
		views = append(views, s.organizationGroupViewWithUsers(group, memberUsers, memberCount[group.GroupID], includeMembers))
	}
	return views, nil
}

func (s *AdminServer) organizationGroupView(group iam.OrganizationGroup, includeMembers bool) (organizationGroupView, error) {
	userIDs, err := s.groupMemberUserIDs(s.db, group.GroupID)
	if err != nil {
		return organizationGroupView{}, err
	}
	users, err := s.loadAdminUsersMap(userIDs)
	if err != nil {
		return organizationGroupView{}, err
	}
	return s.organizationGroupViewWithUsers(group, usersForIDs(users, userIDs), len(userIDs), includeMembers), nil
}

func (s *AdminServer) organizationGroupViewWithUsers(group iam.OrganizationGroup, users []*auth.User, memberCount int, includeMembers bool) organizationGroupView {
	view := organizationGroupView{
		GroupID:        group.GroupID,
		OrganizationID: group.OrganizationID,
		ProviderType:   string(group.ProviderType),
		ProviderID:     group.ProviderID,
		ExternalID:     group.ExternalID,
		DisplayName:    group.DisplayName,
		RoleName:       group.RoleName,
		Editable:       group.ProviderType == iam.IdentityProviderTypeManual,
		MemberCount:    memberCount,
		CreatedAt:      group.CreatedAt,
		UpdatedAt:      group.UpdatedAt,
	}
	if includeMembers {
		view.Members = make([]organizationGroupMemberView, 0, len(users))
		for _, user := range users {
			if user == nil {
				continue
			}
			view.Members = append(view.Members, organizationGroupMemberView{
				UserID:     user.UserID,
				Username:   user.Username,
				Nickname:   user.Nickname,
				Avatar:     user.Avatar,
				UserStatus: string(user.Status),
			})
		}
	}
	return view
}

func (s *AdminServer) loadAdminUsersMap(userIDs []string) (map[string]auth.User, error) {
	userIDs = uniqueTrimmedStrings(userIDs)
	if len(userIDs) == 0 {
		return map[string]auth.User{}, nil
	}
	var users []auth.User
	if err := s.db.Where("user_id IN ?", userIDs).Find(&users).Error; err != nil {
		return nil, err
	}
	result := make(map[string]auth.User, len(users))
	for _, user := range users {
		result[user.UserID] = user
	}
	return result, nil
}

func usersForIDs(users map[string]auth.User, userIDs []string) []*auth.User {
	userIDs = uniqueTrimmedStrings(userIDs)
	result := make([]*auth.User, 0, len(userIDs))
	for _, userID := range userIDs {
		if user, ok := users[userID]; ok {
			userCopy := user
			result = append(result, &userCopy)
			continue
		}
		result = append(result, &auth.User{UserID: userID})
	}
	return result
}

func (s *AdminServer) normalizeOrganizationGroupPayload(req organizationGroupPayload) (string, string, []string, []*auth.User, error) {
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		return "", "", nil, nil, fmt.Errorf("display_name is required")
	}
	roleName, err := normalizeOrganizationGroupRoleName(req.RoleName, displayName)
	if err != nil {
		return "", "", nil, nil, err
	}
	userIDs := uniqueTrimmedStrings(req.UserIDs)
	usersMap, err := s.loadAdminUsersMap(userIDs)
	if err != nil {
		return "", "", nil, nil, err
	}
	users := make([]*auth.User, 0, len(userIDs))
	for _, userID := range userIDs {
		user, ok := usersMap[userID]
		if !ok {
			return "", "", nil, nil, fmt.Errorf("user %q was not found", userID)
		}
		userCopy := user
		users = append(users, &userCopy)
	}
	return displayName, roleName, userIDs, users, nil
}

func (s *AdminServer) groupMemberUserIDs(db *gorm.DB, groupID string) ([]string, error) {
	var userIDs []string
	if err := db.Model(&iam.OrganizationGroupMember{}).Where("group_id = ?", groupID).Order("user_id ASC").Pluck("user_id", &userIDs).Error; err != nil {
		return nil, err
	}
	return uniqueTrimmedStrings(userIDs), nil
}

func (s *AdminServer) replaceOrganizationGroupMembers(tx *gorm.DB, organizationID, groupID string, userIDs []string, now time.Time) error {
	userIDs = uniqueTrimmedStrings(userIDs)
	if err := tx.Delete(&iam.OrganizationGroupMember{}, "group_id = ?", groupID).Error; err != nil {
		return err
	}
	for _, userID := range userIDs {
		member := iam.OrganizationGroupMember{
			OrganizationID: organizationID,
			GroupID:        groupID,
			UserID:         userID,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := tx.Create(&member).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *AdminServer) reconcileManualOrganizationGroupRoles(tx *gorm.DB, organizationID string, userIDs, extraManagedRoles []string, now time.Time) error {
	userIDs = uniqueTrimmedStrings(userIDs)
	if len(userIDs) == 0 {
		return nil
	}
	var managedRoles []string
	if err := tx.Model(&iam.OrganizationGroup{}).
		Where("organization_id = ? AND provider_type = ? AND provider_id = ?", organizationID, iam.IdentityProviderTypeManual, iam.ManualOrganizationGroupProvider).
		Pluck("role_name", &managedRoles).Error; err != nil {
		return err
	}
	managedRoleSet := map[string]struct{}{}
	for _, role := range mergeUniqueStrings(managedRoles, extraManagedRoles) {
		role = strings.TrimSpace(role)
		if role != "" {
			managedRoleSet[strings.ToLower(role)] = struct{}{}
		}
	}

	for _, userID := range userIDs {
		assignedRoles, err := s.manualGroupAssignedRoleNames(tx, organizationID, userID)
		if err != nil {
			return err
		}
		var membership iam.OrganizationMembership
		err = tx.First(&membership, "organization_id = ? AND user_id = ?", organizationID, userID).Error
		switch {
		case err == nil:
			currentRoles := parseRolesJSON(membership.RolesJSON)
			nextRoles := make([]string, 0, len(currentRoles)+len(assignedRoles))
			for _, role := range currentRoles {
				if _, managed := managedRoleSet[strings.ToLower(role)]; managed {
					continue
				}
				nextRoles = append(nextRoles, role)
			}
			nextRoles = append(nextRoles, assignedRoles...)
			_, membership.RolesJSON, err = normalizeRoleList(nextRoles)
			if err != nil {
				return err
			}
			membership.UpdatedAt = now
			if err := tx.Save(&membership).Error; err != nil {
				return err
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			if len(assignedRoles) == 0 {
				continue
			}
			_, rolesJSON, err := normalizeRoleList(assignedRoles)
			if err != nil {
				return err
			}
			membership = iam.OrganizationMembership{
				OrganizationID: organizationID,
				UserID:         userID,
				Status:         iam.MembershipStatusActive,
				RolesJSON:      rolesJSON,
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

func (s *AdminServer) manualGroupAssignedRoleNames(tx *gorm.DB, organizationID, userID string) ([]string, error) {
	var roles []string
	if err := tx.Table("organization_groups").
		Select("organization_groups.role_name").
		Joins("JOIN organization_group_members ON organization_group_members.group_id = organization_groups.group_id").
		Where("organization_groups.organization_id = ? AND organization_groups.provider_type = ? AND organization_groups.provider_id = ? AND organization_group_members.user_id = ?", organizationID, iam.IdentityProviderTypeManual, iam.ManualOrganizationGroupProvider, userID).
		Pluck("organization_groups.role_name", &roles).Error; err != nil {
		return nil, err
	}
	return uniqueTrimmedStrings(roles), nil
}

func adminPagination(c *gin.Context, defaultSize, maxSize int) (int, int) {
	page := 1
	pageSize := defaultSize
	if raw := strings.TrimSpace(c.Query("page")); raw != "" {
		_, _ = fmt.Sscanf(raw, "%d", &page)
	}
	if raw := strings.TrimSpace(c.Query("size")); raw != "" {
		_, _ = fmt.Sscanf(raw, "%d", &pageSize)
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > maxSize {
		pageSize = defaultSize
	}
	return page, pageSize
}

func normalizeOrganizationStatus(raw string) (iam.OrganizationStatus, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return iam.OrganizationStatusActive, nil
	}
	switch iam.OrganizationStatus(raw) {
	case iam.OrganizationStatusActive, iam.OrganizationStatusInactive:
		return iam.OrganizationStatus(raw), nil
	default:
		return "", fmt.Errorf("unsupported organization status %q", raw)
	}
}

func normalizeMembershipStatus(raw string) (iam.MembershipStatus, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return iam.MembershipStatusActive, nil
	}
	switch iam.MembershipStatus(raw) {
	case iam.MembershipStatusActive, iam.MembershipStatusInvited, iam.MembershipStatusDisabled:
		return iam.MembershipStatus(raw), nil
	default:
		return "", fmt.Errorf("unsupported membership status %q", raw)
	}
}

func normalizeOrganizationDomain(raw string) (string, error) {
	domain := strings.TrimSpace(strings.ToLower(raw))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/@") || len(domain) > 253 || !strings.Contains(domain, ".") {
		return "", fmt.Errorf("domain is invalid")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("domain is invalid")
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", fmt.Errorf("domain is invalid")
			}
		}
	}
	return domain, nil
}

func normalizeRoleList(raw []string) ([]string, string, error) {
	seen := map[string]struct{}{}
	roles := make([]string, 0, len(raw))
	for _, role := range raw {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if !roleNamePattern.MatchString(role) {
			return nil, "", fmt.Errorf("role %q is invalid", role)
		}
		key := strings.ToLower(role)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roles = append(roles, role)
	}
	sort.Strings(roles)
	content, err := json.Marshal(roles)
	if err != nil {
		return nil, "", err
	}
	return roles, string(content), nil
}

func normalizeOrganizationGroupRoleName(rawRole, displayName string) (string, error) {
	role := strings.TrimSpace(rawRole)
	if role == "" {
		role = roleNameFromDisplayName(displayName)
	}
	if !roleNamePattern.MatchString(role) {
		return "", fmt.Errorf("role_name %q is invalid", role)
	}
	return role, nil
}

func roleNameFromDisplayName(displayName string) string {
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

func parseRolesJSON(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	var roles []string
	if err := json.Unmarshal([]byte(raw), &roles); err != nil {
		return []string{}
	}
	sort.Strings(roles)
	return roles
}

func uniqueTrimmedStrings(values []string) []string {
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

func mergeUniqueStrings(left, right []string) []string {
	merged := make([]string, 0, len(left)+len(right))
	merged = append(merged, left...)
	merged = append(merged, right...)
	return uniqueTrimmedStrings(merged)
}

func stringKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func marshalMetadata(metadata map[string]any) (string, error) {
	if len(metadata) == 0 {
		return "", nil
	}
	content, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("metadata must be a JSON object")
	}
	return string(content), nil
}

func writeNotFoundOrError(c *gin.Context, err error, notFoundMessage string) {
	if err == nil {
		return
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": notFoundMessage})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}
