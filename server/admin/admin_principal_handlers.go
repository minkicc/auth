package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *AdminServer) handleListAdmins(c *gin.Context) {
	if s == nil || s.accessController == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Admin access controller is not initialized"})
		return
	}

	admins, err := s.accessController.ListAdminPrincipals()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query administrators"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"admins": admins,
		"total":  len(admins),
	})
}

func (s *AdminServer) handleCreateAdmin(c *gin.Context) {
	if s == nil || s.accessController == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Admin access controller is not initialized"})
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
		if trimmedUserID := strings.TrimSpace(req.UserID); trimmedUserID != "" {
			userRef = trimmedUserID
		} else {
			userRef = strings.TrimSpace(req.Username)
		}
	}
	if userRef == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id or username is required"})
		return
	}

	adminView, err := s.accessController.AddDatabaseAdmin(userRef)
	switch {
	case err == nil:
		s.appendSecurityAudit(securityAuditActionAdminPrincipalCreate, pluginAuditActor(c), true, nil, map[string]string{
			"resource_type": "admin_principal",
			"user_id":       adminView.UserID,
			"username":      adminView.Username,
			"sources":       strings.Join(adminView.Sources, ","),
		})
		c.JSON(http.StatusCreated, gin.H{"admin": adminView})
	case errors.Is(err, ErrAdminPrincipalManagedByConfig):
		s.appendSecurityAudit(securityAuditActionAdminPrincipalCreate, pluginAuditActor(c), false, err, map[string]string{
			"resource_type": "admin_principal",
			"user_ref":      userRef,
			"reason":        "managed_by_config",
		})
		c.JSON(http.StatusConflict, gin.H{"error": "This administrator is managed by config and cannot be added from the admin page"})
	case errors.Is(err, ErrAdminPrincipalNotFound):
		s.appendSecurityAudit(securityAuditActionAdminPrincipalCreate, pluginAuditActor(c), false, err, map[string]string{
			"resource_type": "admin_principal",
			"user_ref":      userRef,
			"reason":        "user_not_found",
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
	default:
		s.appendSecurityAudit(securityAuditActionAdminPrincipalCreate, pluginAuditActor(c), false, err, map[string]string{
			"resource_type": "admin_principal",
			"user_ref":      userRef,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create administrator"})
	}
}

func (s *AdminServer) handleDeleteAdmin(c *gin.Context) {
	if s == nil || s.accessController == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Admin access controller is not initialized"})
		return
	}

	userID := strings.TrimSpace(c.Param("user_id"))
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	err := s.accessController.DeleteDatabaseAdmin(userID)
	switch {
	case err == nil:
		s.appendSecurityAudit(securityAuditActionAdminPrincipalDelete, pluginAuditActor(c), true, nil, map[string]string{
			"resource_type": "admin_principal",
			"user_id":       userID,
		})
		c.JSON(http.StatusOK, gin.H{"message": "Administrator removed"})
	case errors.Is(err, ErrAdminPrincipalManagedByConfig):
		s.appendSecurityAudit(securityAuditActionAdminPrincipalDelete, pluginAuditActor(c), false, err, map[string]string{
			"resource_type": "admin_principal",
			"user_id":       userID,
			"reason":        "managed_by_config",
		})
		c.JSON(http.StatusConflict, gin.H{"error": "This administrator is managed by config and can only be changed by operations"})
	case errors.Is(err, ErrAdminPrincipalNotFound):
		s.appendSecurityAudit(securityAuditActionAdminPrincipalDelete, pluginAuditActor(c), false, err, map[string]string{
			"resource_type": "admin_principal",
			"user_id":       userID,
			"reason":        "not_found",
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "Administrator not found"})
	default:
		s.appendSecurityAudit(securityAuditActionAdminPrincipalDelete, pluginAuditActor(c), false, err, map[string]string{
			"resource_type": "admin_principal",
			"user_id":       userID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete administrator"})
	}
}
