package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/oidc"
)

var currentUserOrganizationSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,78}[a-z0-9]$|^[a-z0-9]$`)

type currentUserOrganizationView struct {
	OrganizationID string   `json:"organization_id"`
	Slug           string   `json:"slug,omitempty"`
	Name           string   `json:"name,omitempty"`
	DisplayName    string   `json:"display_name,omitempty"`
	Status         string   `json:"status,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Current        bool     `json:"current"`
}

type currentUserOrganizationsResponse struct {
	Organizations     []currentUserOrganizationView `json:"organizations"`
	PlatformAvailable bool                          `json:"platform_available"`
}

type createCurrentUserOrganizationRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

func (h *AuthHandler) CreateCurrentUserOrganization(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, ok := userID.(string)
	if !ok || strings.TrimSpace(userIDStr) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	if h.accountAuth == nil || h.accountAuth.DB() == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "account database is not available"})
		return
	}
	db := h.accountAuth.DB()
	if !db.Migrator().HasTable(&iam.Organization{}) || !db.Migrator().HasTable(&iam.OrganizationMembership{}) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "organization tables are not available"})
		return
	}

	var req createCurrentUserOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization payload"})
		return
	}

	name := strings.TrimSpace(req.Name)
	displayName := strings.TrimSpace(req.DisplayName)
	if name == "" {
		name = displayName
	}
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if len([]rune(name)) > 120 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name must be at most 120 characters"})
		return
	}
	if displayName == "" {
		displayName = name
	}
	if len([]rune(displayName)) > 120 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "display_name must be at most 120 characters"})
		return
	}

	slug, err := uniqueCurrentUserOrganizationSlug(db, req.Slug, name)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errOrganizationSlugAlreadyExists) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	orgID, err := iam.NewService(db).GenerateOrganizationID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	roles := []string{"owner", "admin"}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	org := iam.Organization{
		OrganizationID: orgID,
		Slug:           slug,
		Name:           name,
		DisplayName:    displayName,
		Status:         iam.OrganizationStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	membership := iam.OrganizationMembership{
		OrganizationID: orgID,
		UserID:         userIDStr,
		Status:         iam.MembershipStatusActive,
		RolesJSON:      string(rolesJSON),
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		return tx.Create(&membership).Error
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	view := currentUserOrganizationView{
		OrganizationID: org.OrganizationID,
		Slug:           org.Slug,
		Name:           org.Name,
		DisplayName:    org.DisplayName,
		Status:         string(org.Status),
		Roles:          roles,
		Current:        false,
	}
	c.JSON(http.StatusCreated, gin.H{
		"organization":       view,
		"organizations":      []currentUserOrganizationView{view},
		"platform_available": true,
	})
}

func (h *AuthHandler) GetCurrentUserOrganizations(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, ok := userID.(string)
	if !ok || strings.TrimSpace(userIDStr) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	if h.accountAuth == nil || h.accountAuth.DB() == nil {
		c.JSON(http.StatusOK, currentUserOrganizationsResponse{Organizations: []currentUserOrganizationView{}, PlatformAvailable: true})
		return
	}
	db := h.accountAuth.DB()
	if !db.Migrator().HasTable(&iam.OrganizationMembership{}) {
		c.JSON(http.StatusOK, currentUserOrganizationsResponse{Organizations: []currentUserOrganizationView{}, PlatformAvailable: true})
		return
	}

	var memberships []iam.OrganizationMembership
	if err := db.Where("user_id = ? AND status = ?", userIDStr, iam.MembershipStatusActive).
		Order("created_at ASC").
		Find(&memberships).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	platformAvailable := true
	if clientID := strings.TrimSpace(c.Query("client_id")); clientID != "" && h.oidcProvider != nil {
		scope := strings.Join(strings.Fields(c.Query("scope")), " ")
		var err error
		platformAvailable, err = h.oidcProvider.PlatformContextAllowedForClient(clientID, scope)
		switch {
		case errors.Is(err, oidc.ErrClientNotFound):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		allowedOrgIDs, filtered, err := h.oidcProvider.AuthorizedOrganizationIDsForClient(userIDStr, clientID, scope)
		switch {
		case errors.Is(err, oidc.ErrClientNotFound):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		case err != nil:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		case filtered:
			filteredMemberships := make([]iam.OrganizationMembership, 0, len(memberships))
			for _, membership := range memberships {
				if _, ok := allowedOrgIDs[membership.OrganizationID]; ok {
					filteredMemberships = append(filteredMemberships, membership)
				}
			}
			memberships = filteredMemberships
		}
	}
	if len(memberships) == 0 {
		c.JSON(http.StatusOK, currentUserOrganizationsResponse{Organizations: []currentUserOrganizationView{}, PlatformAvailable: platformAvailable})
		return
	}

	orgIDs := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		orgIDs = append(orgIDs, membership.OrganizationID)
	}

	orgMap := map[string]iam.Organization{}
	if db.Migrator().HasTable(&iam.Organization{}) {
		var orgs []iam.Organization
		if err := db.Where("organization_id IN ?", orgIDs).Find(&orgs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, org := range orgs {
			orgMap[org.OrganizationID] = org
		}
	}

	currentOrgIDStr := ""
	currentOrgSlugStr := ""
	if activeScope, ok, err := h.loadUserActiveScope(db, userIDStr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	} else if ok && activeScope.ScopeType == auth.UserActiveScopeTypeEnterprise {
		currentOrgIDStr = activeScope.OrganizationID
		currentOrgSlugStr = activeScope.OrganizationSlug
	} else if !ok {
		currentOrgID, _ := c.Get("org_id")
		currentOrgIDStr, _ = currentOrgID.(string)
		currentOrgSlug, _ := c.Get("org_slug")
		currentOrgSlugStr, _ = currentOrgSlug.(string)
	}
	iamService := iam.NewService(db)

	views := make([]currentUserOrganizationView, 0, len(memberships))
	for _, membership := range memberships {
		org := orgMap[membership.OrganizationID]
		view := currentUserOrganizationView{
			OrganizationID: membership.OrganizationID,
			Current:        membership.OrganizationID == currentOrgIDStr,
		}
		authz, err := iamService.ResolveOrganizationAuthorization(userIDStr, membership.OrganizationID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if err == nil {
			view.Roles = authz.RoleSlugs
			view.Groups = authz.GroupNames
		}
		if org.OrganizationID != "" {
			view.Slug = org.Slug
			view.Name = org.Name
			view.DisplayName = org.DisplayName
			view.Status = string(org.Status)
			if !view.Current && currentOrgSlugStr != "" && strings.EqualFold(org.Slug, currentOrgSlugStr) {
				view.Current = true
			}
		}
		views = append(views, view)
	}

	c.JSON(http.StatusOK, currentUserOrganizationsResponse{Organizations: views, PlatformAvailable: platformAvailable})
}

var errOrganizationSlugAlreadyExists = errors.New("organization slug already exists")

func uniqueCurrentUserOrganizationSlug(db *gorm.DB, requestedSlug string, name string) (string, error) {
	explicit := strings.TrimSpace(requestedSlug) != ""
	source := requestedSlug
	if strings.TrimSpace(source) == "" {
		source = name
	}
	base := normalizeCurrentUserOrganizationSlug(source)
	if explicit && base == "" {
		return "", fmt.Errorf("slug must use lowercase letters, numbers, and hyphens")
	}
	if base == "" {
		base = "enterprise"
	}
	if !currentUserOrganizationSlugPattern.MatchString(base) {
		return "", fmt.Errorf("slug must use lowercase letters, numbers, and hyphens")
	}

	exists, err := organizationSlugExists(db, base)
	if err != nil {
		return "", err
	}
	if !exists {
		return base, nil
	}
	if explicit {
		return "", errOrganizationSlugAlreadyExists
	}

	for i := 0; i < 10; i++ {
		suffix, err := auth.GenerateReadableRandomString(8)
		if err != nil {
			return "", err
		}
		prefix := base
		maxPrefixLength := 80 - len(suffix) - 1
		if len(prefix) > maxPrefixLength {
			prefix = strings.TrimRight(prefix[:maxPrefixLength], "-")
		}
		if prefix == "" {
			prefix = "enterprise"
		}
		candidate := prefix + "-" + suffix
		exists, err := organizationSlugExists(db, candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique organization slug")
}

func normalizeCurrentUserOrganizationSlug(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	var builder strings.Builder
	lastHyphen := false
	for _, ch := range raw {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			builder.WriteRune(ch)
			lastHyphen = false
			continue
		}
		if builder.Len() > 0 && !lastHyphen {
			builder.WriteByte('-')
			lastHyphen = true
		}
	}
	slug := strings.Trim(builder.String(), "-")
	if len(slug) > 80 {
		slug = strings.TrimRight(slug[:80], "-")
	}
	return slug
}

func organizationSlugExists(db *gorm.DB, slug string) (bool, error) {
	var count int64
	if err := db.Model(&iam.Organization{}).Where("slug = ?", slug).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
