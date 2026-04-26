package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *AdminServer) handleListOrganizationAdmins(c *gin.Context) {
	if s == nil || s.accessController == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Admin access controller is not initialized"})
		return
	}
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	admins, err := s.accessController.ListOrganizationAdminPrincipals(org.OrganizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query organization administrators"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"admins": admins,
		"total":  len(admins),
	})
}

func (s *AdminServer) handleCreateOrganizationAdmin(c *gin.Context) {
	if s == nil || s.accessController == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Admin access controller is not initialized"})
		return
	}
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}

	var req struct {
		UserID   string `json:"user_id"`
		Username string `json:"username"`
		UserRef  string `json:"user_ref"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}
	userRef := strings.TrimSpace(req.UserRef)
	if userRef == "" {
		if userID := strings.TrimSpace(req.UserID); userID != "" {
			userRef = userID
		} else {
			userRef = strings.TrimSpace(req.Username)
		}
	}
	if userRef == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id or username is required"})
		return
	}

	view, err := s.accessController.AddOrganizationAdmin(org.OrganizationID, userRef)
	switch {
	case err == nil:
		s.appendSecurityAudit(securityAuditActionOrganizationAdminCreate, pluginAuditActor(c), true, nil, map[string]string{
			"resource_type":     "organization_admin",
			"organization_id":   org.OrganizationID,
			"organization_slug": org.Slug,
			"user_id":           view.UserID,
			"username":          view.Username,
		})
		c.JSON(http.StatusCreated, gin.H{"admin": view})
	case errors.Is(err, ErrAdminPrincipalNotFound):
		s.appendSecurityAudit(securityAuditActionOrganizationAdminCreate, pluginAuditActor(c), false, err, map[string]string{
			"resource_type":   "organization_admin",
			"organization_id": org.OrganizationID,
			"user_ref":        userRef,
			"reason":          "user_not_found",
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
	default:
		s.appendSecurityAudit(securityAuditActionOrganizationAdminCreate, pluginAuditActor(c), false, err, map[string]string{
			"resource_type":   "organization_admin",
			"organization_id": org.OrganizationID,
			"user_ref":        userRef,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create organization administrator"})
	}
}

func (s *AdminServer) handleDeleteOrganizationAdmin(c *gin.Context) {
	if s == nil || s.accessController == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Admin access controller is not initialized"})
		return
	}
	org, ok := s.loadOrganization(c, c.Param("id"))
	if !ok {
		return
	}
	userID := strings.TrimSpace(c.Param("user_id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	err := s.accessController.DeleteOrganizationAdmin(org.OrganizationID, userID)
	switch {
	case err == nil:
		s.appendSecurityAudit(securityAuditActionOrganizationAdminDelete, pluginAuditActor(c), true, nil, map[string]string{
			"resource_type":     "organization_admin",
			"organization_id":   org.OrganizationID,
			"organization_slug": org.Slug,
			"user_id":           userID,
		})
		c.JSON(http.StatusOK, gin.H{"message": "Organization administrator removed"})
	case errors.Is(err, ErrAdminPrincipalNotFound):
		s.appendSecurityAudit(securityAuditActionOrganizationAdminDelete, pluginAuditActor(c), false, err, map[string]string{
			"resource_type":   "organization_admin",
			"organization_id": org.OrganizationID,
			"user_id":         userID,
			"reason":          "not_found",
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "Organization administrator not found"})
	default:
		s.appendSecurityAudit(securityAuditActionOrganizationAdminDelete, pluginAuditActor(c), false, err, map[string]string{
			"resource_type":   "organization_admin",
			"organization_id": org.OrganizationID,
			"user_id":         userID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete organization administrator"})
	}
}
