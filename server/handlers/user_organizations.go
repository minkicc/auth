package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/iam"
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

	groupMap, err := organizationGroupDisplayNamesForUser(db, userIDStr, orgIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	currentOrgID, _ := c.Get("org_id")
	currentOrgIDStr, _ := currentOrgID.(string)
	currentOrgSlug, _ := c.Get("org_slug")
	currentOrgSlugStr, _ := currentOrgSlug.(string)

	views := make([]currentUserOrganizationView, 0, len(memberships))
	for _, membership := range memberships {
		org := orgMap[membership.OrganizationID]
		view := currentUserOrganizationView{
			OrganizationID: membership.OrganizationID,
			Roles:          parseStringListJSON(membership.RolesJSON),
			Groups:         groupMap[membership.OrganizationID],
			Current:        membership.OrganizationID == currentOrgIDStr,
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

func organizationGroupDisplayNamesForUser(db *gorm.DB, userID string, organizationIDs []string) (map[string][]string, error) {
	result := map[string][]string{}
	if db == nil || userID == "" || len(organizationIDs) == 0 || !db.Migrator().HasTable(&iam.OrganizationGroup{}) || !db.Migrator().HasTable(&iam.OrganizationGroupMember{}) {
		return result, nil
	}

	var rows []struct {
		OrganizationID string
		DisplayName    string
	}
	if err := db.Table("organization_groups").
		Select("organization_groups.organization_id, organization_groups.display_name").
		Joins("JOIN organization_group_members ON organization_group_members.group_id = organization_groups.group_id AND organization_group_members.organization_id = organization_groups.organization_id").
		Where("organization_group_members.user_id = ? AND organization_groups.organization_id IN ?", userID, organizationIDs).
		Order("organization_groups.display_name ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	for _, row := range rows {
		result[row.OrganizationID] = append(result[row.OrganizationID], row.DisplayName)
	}
	for organizationID, groups := range result {
		result[organizationID] = uniqueStrings(groups)
	}
	return result, nil
}
