package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"example.com/auth/server/auth"
	"example.com/auth/server/iam"
)

type currentUserActiveScopeRequest struct {
	ScopeType           string `json:"scope_type"`
	OrganizationContext string `json:"organization_context"`
	OrganizationID      string `json:"organization_id"`
	OrganizationSlug    string `json:"organization_slug"`
	ScopeID             string `json:"scope_id"`
}

type currentUserActiveScopeView struct {
	ScopeType        string   `json:"scope_type"`
	OrganizationID   string   `json:"organization_id,omitempty"`
	OrganizationSlug string   `json:"organization_slug,omitempty"`
	OrganizationName string   `json:"organization_name,omitempty"`
	Roles            []string `json:"roles,omitempty"`
	Groups           []string `json:"groups,omitempty"`
}

func (h *AuthHandler) GetCurrentUserActiveScope(c *gin.Context) {
	userID, db, ok := h.currentUserAndDB(c)
	if !ok {
		return
	}

	activeScope, found, err := h.loadUserActiveScope(db, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !found || activeScope.ScopeType != auth.UserActiveScopeTypeEnterprise {
		c.JSON(http.StatusOK, gin.H{"active_scope": platformActiveScopeView(), "scope_type": auth.UserActiveScopeTypePlatform})
		return
	}

	view, err := h.enterpriseActiveScopeView(db, userID, activeScope.OrganizationID, activeScope.OrganizationSlug)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || isPermissionDeniedError(err) {
			_ = h.persistUserActiveScope(db, userID, platformActiveScopeView())
			c.JSON(http.StatusOK, gin.H{"active_scope": platformActiveScopeView(), "scope_type": auth.UserActiveScopeTypePlatform})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, activeScopeResponse(view))
}

func (h *AuthHandler) SetCurrentUserActiveScope(c *gin.Context) {
	userID, db, ok := h.currentUserAndDB(c)
	if !ok {
		return
	}

	var req currentUserActiveScopeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid active scope payload"})
		return
	}

	scopeType := strings.TrimSpace(req.ScopeType)
	context := strings.TrimSpace(req.OrganizationContext)
	if scopeType == "" {
		switch strings.ToLower(context) {
		case "", auth.UserActiveScopeTypePlatform:
			scopeType = auth.UserActiveScopeTypePlatform
		default:
			scopeType = auth.UserActiveScopeTypeEnterprise
		}
	}
	scopeType = strings.ToLower(scopeType)

	var view currentUserActiveScopeView
	switch scopeType {
	case auth.UserActiveScopeTypePlatform:
		view = platformActiveScopeView()
	case auth.UserActiveScopeTypeEnterprise:
		candidate := firstNonEmpty(req.OrganizationID, req.OrganizationSlug, req.ScopeID, context)
		if candidate == "" || strings.EqualFold(candidate, auth.UserActiveScopeTypePlatform) || candidate == "0" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "organization_id is required"})
			return
		}
		var err error
		view, err = h.enterpriseActiveScopeView(db, userID, candidate, "")
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, gorm.ErrRecordNotFound) {
				status = http.StatusNotFound
			} else if isPermissionDeniedError(err) {
				status = http.StatusForbidden
			}
			c.JSON(status, gin.H{"error": err.Error()})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "scope_type must be platform or enterprise"})
		return
	}

	if err := h.persistUserActiveScope(db, userID, view); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, activeScopeResponse(view))
}

func (h *AuthHandler) currentUserAndDB(c *gin.Context) (string, *gorm.DB, bool) {
	userID, _ := c.Get("user_id")
	userIDStr, ok := userID.(string)
	userIDStr = strings.TrimSpace(userIDStr)
	if !ok || userIDStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return "", nil, false
	}
	if h.accountAuth == nil || h.accountAuth.DB() == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "account database is not available"})
		return "", nil, false
	}
	return userIDStr, h.accountAuth.DB(), true
}

func (h *AuthHandler) loadUserActiveScope(db *gorm.DB, userID string) (auth.UserActiveScope, bool, error) {
	if db == nil || !db.Migrator().HasTable(&auth.UserActiveScope{}) {
		return auth.UserActiveScope{}, false, nil
	}
	var activeScope auth.UserActiveScope
	if err := db.Where("user_id = ?", strings.TrimSpace(userID)).First(&activeScope).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return auth.UserActiveScope{}, false, nil
		}
		return auth.UserActiveScope{}, false, err
	}
	activeScope.ScopeType = strings.ToLower(strings.TrimSpace(activeScope.ScopeType))
	if activeScope.ScopeType == "" {
		activeScope.ScopeType = auth.UserActiveScopeTypePlatform
	}
	activeScope.OrganizationID = strings.TrimSpace(activeScope.OrganizationID)
	activeScope.OrganizationSlug = strings.TrimSpace(activeScope.OrganizationSlug)
	activeScope.OrganizationName = strings.TrimSpace(activeScope.OrganizationName)
	return activeScope, true, nil
}

func (h *AuthHandler) persistUserActiveScope(db *gorm.DB, userID string, view currentUserActiveScopeView) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return auth.ErrInvalidToken("missing user context")
	}
	now := time.Now()
	updates := map[string]any{
		"scope_type":        strings.TrimSpace(view.ScopeType),
		"organization_id":   strings.TrimSpace(view.OrganizationID),
		"organization_slug": strings.TrimSpace(view.OrganizationSlug),
		"organization_name": strings.TrimSpace(view.OrganizationName),
		"updated_at":        now,
	}
	var existing auth.UserActiveScope
	if err := db.Where("user_id = ?", userID).First(&existing).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return db.Create(&auth.UserActiveScope{
			UserID:           userID,
			ScopeType:        strings.TrimSpace(view.ScopeType),
			OrganizationID:   strings.TrimSpace(view.OrganizationID),
			OrganizationSlug: strings.TrimSpace(view.OrganizationSlug),
			OrganizationName: strings.TrimSpace(view.OrganizationName),
			CreatedAt:        now,
			UpdatedAt:        now,
		}).Error
	}
	return db.Model(&existing).Updates(updates).Error
}

func (h *AuthHandler) enterpriseActiveScopeView(db *gorm.DB, userID, organizationID, organizationSlug string) (currentUserActiveScopeView, error) {
	candidate := firstNonEmpty(organizationID, organizationSlug)
	resolvedOrgID, resolvedSlug, err := h.lookupAuthorizedOrganizationCandidate(db, userID, candidate)
	if err != nil {
		return currentUserActiveScopeView{}, err
	}

	view := currentUserActiveScopeView{
		ScopeType:        auth.UserActiveScopeTypeEnterprise,
		OrganizationID:   resolvedOrgID,
		OrganizationSlug: resolvedSlug,
	}
	if db.Migrator().HasTable(&iam.Organization{}) {
		var organization iam.Organization
		if err := db.Where("organization_id = ?", resolvedOrgID).First(&organization).Error; err == nil {
			view.OrganizationSlug = firstNonEmpty(view.OrganizationSlug, organization.Slug)
			view.OrganizationName = firstNonEmpty(organization.DisplayName, organization.Name)
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return currentUserActiveScopeView{}, err
		}
	}
	if authz, err := iam.NewService(db).ResolveOrganizationAuthorization(userID, resolvedOrgID); err == nil {
		view.Roles = authz.RoleSlugs
		view.Groups = authz.GroupNames
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return currentUserActiveScopeView{}, err
	}
	return view, nil
}

func platformActiveScopeView() currentUserActiveScopeView {
	return currentUserActiveScopeView{ScopeType: auth.UserActiveScopeTypePlatform}
}

func activeScopeResponse(view currentUserActiveScopeView) gin.H {
	scopeID := "0"
	scopeName := ""
	if view.ScopeType == auth.UserActiveScopeTypeEnterprise {
		scopeID = view.OrganizationID
		scopeName = view.OrganizationName
	}
	return gin.H{
		"active_scope":      view,
		"scope_type":        view.ScopeType,
		"scope_id":          scopeID,
		"scope_name":        scopeName,
		"organization_id":   view.OrganizationID,
		"organization_slug": view.OrganizationSlug,
		"organization_name": view.OrganizationName,
		"roles":             view.Roles,
		"groups":            view.Groups,
	}
}

func isPermissionDeniedError(err error) bool {
	var appErr *auth.AppError
	return errors.As(err, &appErr) && appErr.Code == auth.ErrCodePermissionDenied
}
