/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/iam"
)

type invitationCreatePayload struct {
	Name           string   `json:"name"`
	Code           string   `json:"code"`
	Scope          string   `json:"scope"`
	OrganizationID string   `json:"organization_id"`
	ClientID       string   `json:"client_id"`
	MaxUses        int      `json:"max_uses"`
	ExpiresAt      string   `json:"expires_at"`
	AllowedEmail   string   `json:"allowed_email"`
	AllowedDomain  string   `json:"allowed_domain"`
	DefaultRoles   []string `json:"default_roles"`
	DefaultGroups  []string `json:"default_groups"`
}

func (s *AdminServer) handleListInvitations(c *gin.Context) {
	invitations, err := iam.NewService(s.db).ListInvitations()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query invitations"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"invitations": invitations,
		"total":       len(invitations),
	})
}

func (s *AdminServer) handleCreateInvitation(c *gin.Context) {
	var req invitationCreatePayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid invitation payload"})
		return
	}

	expiresAt, err := parseOptionalInvitationExpiry(req.ExpiresAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID, _ := c.Get("user_id")
	invitation, code, err := iam.NewService(s.db).CreateInvitation(iam.InvitationCreateInput{
		Name:           req.Name,
		Code:           req.Code,
		Scope:          req.Scope,
		OrganizationID: req.OrganizationID,
		ClientID:       req.ClientID,
		MaxUses:        req.MaxUses,
		ExpiresAt:      expiresAt,
		AllowedEmail:   req.AllowedEmail,
		AllowedDomain:  req.AllowedDomain,
		DefaultRoles:   req.DefaultRoles,
		DefaultGroups:  req.DefaultGroups,
		CreatedBy:      stringFromContextValue(actorID),
	})
	if err != nil {
		s.appendSecurityAudit(securityAuditActionInvitationCreate, pluginAuditActor(c), false, err, map[string]string{
			"resource_type":   "invitation",
			"name":            strings.TrimSpace(req.Name),
			"scope":           strings.TrimSpace(req.Scope),
			"organization_id": strings.TrimSpace(req.OrganizationID),
			"client_id":       strings.TrimSpace(req.ClientID),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.appendSecurityAudit(securityAuditActionInvitationCreate, pluginAuditActor(c), true, nil, map[string]string{
		"resource_type":   "invitation",
		"invitation_id":   invitation.InvitationID,
		"name":            invitation.Name,
		"scope":           string(invitation.Scope),
		"organization_id": invitation.OrganizationID,
		"client_id":       invitation.ClientID,
	})
	c.JSON(http.StatusCreated, gin.H{
		"invitation": invitation,
		"code":       code,
	})
}

func (s *AdminServer) handleDisableInvitation(c *gin.Context) {
	invitationID := strings.TrimSpace(c.Param("id"))
	if invitationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invitation_id is required"})
		return
	}

	err := iam.NewService(s.db).DisableInvitation(invitationID)
	switch {
	case err == nil:
		s.appendSecurityAudit(securityAuditActionInvitationDisable, pluginAuditActor(c), true, nil, map[string]string{
			"resource_type": "invitation",
			"invitation_id": invitationID,
		})
		c.JSON(http.StatusOK, gin.H{"message": "Invitation disabled"})
	case errors.Is(err, gorm.ErrRecordNotFound):
		s.appendSecurityAudit(securityAuditActionInvitationDisable, pluginAuditActor(c), false, err, map[string]string{
			"resource_type": "invitation",
			"invitation_id": invitationID,
			"reason":        "not_found",
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "Invitation not found"})
	default:
		s.appendSecurityAudit(securityAuditActionInvitationDisable, pluginAuditActor(c), false, err, map[string]string{
			"resource_type": "invitation",
			"invitation_id": invitationID,
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable invitation"})
	}
}

func parseOptionalInvitationExpiry(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return &parsed, nil
	}
	if parsed, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
		return &parsed, nil
	}
	if parsed, err := time.Parse("2006-01-02", value); err == nil {
		return &parsed, nil
	}
	return nil, errors.New("expires_at must be RFC3339, YYYY-MM-DD HH:mm:ss, or YYYY-MM-DD")
}

func stringFromContextValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}
