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
