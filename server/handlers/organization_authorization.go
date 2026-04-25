package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/iam"
)

const organizationAuthorizationContextKey = "organization_authorization"

var errOrganizationSelectionRequired = errors.New("organization_selection_required")

type currentOrganizationAuthorizationView struct {
	OrganizationID   string   `json:"organization_id"`
	OrganizationSlug string   `json:"organization_slug,omitempty"`
	Roles            []string `json:"roles,omitempty"`
	Groups           []string `json:"groups,omitempty"`
	Permissions      []string `json:"permissions,omitempty"`
}

func (h *AuthHandler) RequireOrganizationContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, _, err := h.currentOrganizationAuthorization(c); err != nil {
			h.abortOrganizationAuthorizationError(c, err)
			return
		}
		c.Next()
	}
}

func (h *AuthHandler) RequireOrganizationAuthorization(requirement iam.OrganizationAuthorizationRequirement) gin.HandlerFunc {
	return func(c *gin.Context) {
		authz, _, err := h.currentOrganizationAuthorization(c)
		if err != nil {
			h.abortOrganizationAuthorizationError(c, err)
			return
		}
		if !iam.OrganizationAuthorizationMatches(authz, requirement) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "permission_denied"})
			return
		}
		c.Next()
	}
}

func (h *AuthHandler) RequireOrganizationRole(roles ...string) gin.HandlerFunc {
	return h.RequireOrganizationAuthorization(iam.OrganizationAuthorizationRequirement{
		RequireOrganization: true,
		AnyRoles:            roles,
	})
}

func (h *AuthHandler) RequireOrganizationGroup(groups ...string) gin.HandlerFunc {
	return h.RequireOrganizationAuthorization(iam.OrganizationAuthorizationRequirement{
		RequireOrganization: true,
		AnyGroups:           groups,
	})
}

func (h *AuthHandler) RequireOrganizationPermission(permissionKeys ...string) gin.HandlerFunc {
	return h.RequireOrganizationAuthorization(iam.OrganizationAuthorizationRequirement{
		RequireOrganization: true,
		AnyPermissions:      permissionKeys,
	})
}

func (h *AuthHandler) GetCurrentOrganizationAuthorization(c *gin.Context) {
	authz, orgSlug, err := h.currentOrganizationAuthorization(c)
	if err != nil {
		h.abortOrganizationAuthorizationError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"authorization": currentOrganizationAuthorizationView{
			OrganizationID:   authz.OrganizationID,
			OrganizationSlug: orgSlug,
			Roles:            authz.RoleSlugs,
			Groups:           authz.GroupNames,
			Permissions:      authz.PermissionKeys,
		},
	})
}

func (h *AuthHandler) currentOrganizationAuthorization(c *gin.Context) (iam.OrganizationAuthorization, string, error) {
	if cached, ok := c.Get(organizationAuthorizationContextKey); ok {
		if result, ok := cached.(currentOrganizationAuthorizationView); ok {
			return iam.OrganizationAuthorization{
				OrganizationID: result.OrganizationID,
				RoleSlugs:      append([]string(nil), result.Roles...),
				GroupNames:     append([]string(nil), result.Groups...),
				PermissionKeys: append([]string(nil), result.Permissions...),
			}, result.OrganizationSlug, nil
		}
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	userIDStr = strings.TrimSpace(userIDStr)
	if userIDStr == "" {
		return iam.OrganizationAuthorization{}, "", auth.ErrInvalidToken("missing user context")
	}

	organizationID, organizationSlug, err := h.resolveCurrentOrganizationContext(c, userIDStr)
	if err != nil {
		return iam.OrganizationAuthorization{}, "", err
	}

	service := iam.NewService(h.accountAuth.DB())
	authz, err := service.ResolveOrganizationAuthorization(userIDStr, organizationID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return iam.OrganizationAuthorization{}, "", auth.NewPermissionDeniedError("organization access denied")
		}
		return iam.OrganizationAuthorization{}, "", err
	}

	view := currentOrganizationAuthorizationView{
		OrganizationID:   authz.OrganizationID,
		OrganizationSlug: organizationSlug,
		Roles:            authz.RoleSlugs,
		Groups:           authz.GroupNames,
		Permissions:      authz.PermissionKeys,
	}
	c.Set("org_id", authz.OrganizationID)
	if organizationSlug != "" {
		c.Set("org_slug", organizationSlug)
	}
	c.Set(organizationAuthorizationContextKey, view)
	return authz, organizationSlug, nil
}

func (h *AuthHandler) resolveCurrentOrganizationContext(c *gin.Context, userID string) (string, string, error) {
	if orgID, _ := c.Get("org_id"); strings.TrimSpace(toString(orgID)) != "" {
		return strings.TrimSpace(toString(orgID)), strings.TrimSpace(toString(ginContextValue(c, "org_slug"))), nil
	}

	candidate := strings.TrimSpace(c.Query("organization_id"))
	if candidate == "" {
		candidate = strings.TrimSpace(c.GetHeader("X-Organization-ID"))
	}
	if candidate == "" {
		candidate = strings.TrimSpace(c.Query("org_hint"))
	}
	if candidate == "" {
		candidate = strings.TrimSpace(c.GetHeader("X-Organization-Hint"))
	}

	db := h.accountAuth.DB()
	if db == nil {
		return "", "", gorm.ErrRecordNotFound
	}

	if candidate != "" {
		organizationID, organizationSlug, err := h.lookupAuthorizedOrganizationCandidate(db, userID, candidate)
		if err != nil {
			return "", "", err
		}
		return organizationID, organizationSlug, nil
	}

	var memberships []iam.OrganizationMembership
	if err := db.Where("user_id = ? AND status = ?", userID, iam.MembershipStatusActive).
		Order("created_at ASC").
		Limit(2).
		Find(&memberships).Error; err != nil {
		return "", "", err
	}
	switch len(memberships) {
	case 0:
		return "", "", gorm.ErrRecordNotFound
	case 1:
		slug, _ := h.lookupOrganizationSlug(db, memberships[0].OrganizationID)
		return memberships[0].OrganizationID, slug, nil
	default:
		return "", "", errOrganizationSelectionRequired
	}
}

func (h *AuthHandler) lookupAuthorizedOrganizationCandidate(db *gorm.DB, userID, candidate string) (string, string, error) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", "", gorm.ErrRecordNotFound
	}

	organizationID := candidate
	organizationSlug := ""
	if slug, err := h.lookupOrganizationSlug(db, candidate); err == nil {
		organizationSlug = slug
	}
	if organizationSlug == "" && db.Migrator().HasTable(&iam.Organization{}) {
		var organization iam.Organization
		if err := db.Where("organization_id = ? OR slug = ?", candidate, candidate).First(&organization).Error; err == nil {
			organizationID = organization.OrganizationID
			organizationSlug = organization.Slug
		}
	}

	var membership iam.OrganizationMembership
	if err := db.Where("user_id = ? AND organization_id = ? AND status = ?", userID, organizationID, iam.MembershipStatusActive).
		First(&membership).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", auth.NewPermissionDeniedError("organization access denied")
		}
		return "", "", err
	}

	if organizationSlug == "" {
		organizationSlug, _ = h.lookupOrganizationSlug(db, membership.OrganizationID)
	}
	return membership.OrganizationID, organizationSlug, nil
}

func (h *AuthHandler) lookupOrganizationSlug(db *gorm.DB, organizationID string) (string, error) {
	if db == nil || !db.Migrator().HasTable(&iam.Organization{}) {
		return "", gorm.ErrRecordNotFound
	}
	var organization iam.Organization
	if err := db.Where("organization_id = ?", organizationID).First(&organization).Error; err != nil {
		return "", err
	}
	return organization.Slug, nil
}

func (h *AuthHandler) abortOrganizationAuthorizationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errOrganizationSelectionRequired):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "organization_selection_required"})
	case errors.Is(err, gorm.ErrRecordNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "organization_not_found"})
	default:
		var appErr *auth.AppError
		if errors.As(err, &appErr) {
			message := strings.TrimSpace(appErr.Message)
			if message == "" {
				message = "forbidden"
			}
			c.AbortWithStatusJSON(appErr.GetHTTPStatus(), gin.H{"error": message})
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}

func ginContextValue(c *gin.Context, key string) any {
	value, _ := c.Get(key)
	return value
}

func toString(value any) string {
	str, _ := value.(string)
	return str
}
