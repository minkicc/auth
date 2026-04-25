package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/oidc"
)

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

func (h *AuthHandler) GetCurrentUserOrganizations(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, ok := userID.(string)
	if !ok || strings.TrimSpace(userIDStr) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	if h.accountAuth == nil || h.accountAuth.DB() == nil {
		c.JSON(http.StatusOK, gin.H{"organizations": []currentUserOrganizationView{}})
		return
	}
	db := h.accountAuth.DB()
	if !db.Migrator().HasTable(&iam.OrganizationMembership{}) {
		c.JSON(http.StatusOK, gin.H{"organizations": []currentUserOrganizationView{}})
		return
	}

	var memberships []iam.OrganizationMembership
	if err := db.Where("user_id = ? AND status = ?", userIDStr, iam.MembershipStatusActive).
		Order("created_at ASC").
		Find(&memberships).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if clientID := strings.TrimSpace(c.Query("client_id")); clientID != "" && h.oidcProvider != nil {
		scope := strings.Join(strings.Fields(c.Query("scope")), " ")
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
		c.JSON(http.StatusOK, gin.H{"organizations": []currentUserOrganizationView{}})
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

	currentOrgID, _ := c.Get("org_id")
	currentOrgIDStr, _ := currentOrgID.(string)
	currentOrgSlug, _ := c.Get("org_slug")
	currentOrgSlugStr, _ := currentOrgSlug.(string)
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

	c.JSON(http.StatusOK, gin.H{"organizations": views})
}
