package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"example.com/auth/server/config"
	"example.com/auth/server/iam"
)

const trustedOrganizationReadScope = "read:organizations"

type trustedOrganizationView struct {
	OrganizationID string    `json:"organization_id"`
	Slug           string    `json:"slug,omitempty"`
	Name           string    `json:"name,omitempty"`
	DisplayName    string    `json:"display_name,omitempty"`
	Status         string    `json:"status,omitempty"`
	OwnerUserID    string    `json:"owner_user_id,omitempty"`
	MemberCount    int64     `json:"member_count"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (h *AuthHandler) GetTrustedOrganizations(c *gin.Context) {
	trustedClient, exists := c.Get("trusted_client")
	if !exists {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足"})
		return
	}
	client, ok := trustedClient.(*config.TrustedClient)
	if !ok || client == nil || !client.HasScope(trustedOrganizationReadScope) {
		c.JSON(http.StatusForbidden, gin.H{"error": "权限不足"})
		return
	}
	if h == nil || h.accountAuth == nil || h.accountAuth.DB() == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "account database is not available"})
		return
	}
	db := h.accountAuth.DB()
	if !db.Migrator().HasTable(&iam.Organization{}) || !db.Migrator().HasTable(&iam.OrganizationMembership{}) {
		c.JSON(http.StatusOK, gin.H{
			"organizations": []trustedOrganizationView{},
			"total":         int64(0),
			"page":          1,
			"page_size":     100,
		})
		return
	}

	page := queryInt(c, "page", 1)
	if page < 1 {
		page = 1
	}
	pageSize := queryInt(c, "page_size", 100)
	if pageSize < 1 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	query := db.Model(&iam.Organization{})
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if search := strings.TrimSpace(c.Query("search")); search != "" {
		like := "%" + search + "%"
		query = query.Where("organization_id LIKE ? OR slug LIKE ? OR name LIKE ? OR display_name LIKE ?", like, like, like, like)
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

	orgIDs := make([]string, 0, len(organizations))
	for _, organization := range organizations {
		if strings.TrimSpace(organization.OrganizationID) != "" {
			orgIDs = append(orgIDs, organization.OrganizationID)
		}
	}

	memberCounts := map[string]int64{}
	ownerUserIDs := map[string]string{}
	if len(orgIDs) > 0 {
		var memberships []iam.OrganizationMembership
		if err := db.Where("organization_id IN ? AND status = ?", orgIDs, iam.MembershipStatusActive).
			Order("created_at ASC").
			Find(&memberships).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, membership := range memberships {
			orgID := strings.TrimSpace(membership.OrganizationID)
			if orgID == "" {
				continue
			}
			memberCounts[orgID]++
			if ownerUserIDs[orgID] == "" {
				ownerUserIDs[orgID] = membership.UserID
			}
			if rolesJSONContains(membership.RolesJSON, "owner") {
				ownerUserIDs[orgID] = membership.UserID
			}
		}
	}

	views := make([]trustedOrganizationView, 0, len(organizations))
	for _, organization := range organizations {
		views = append(views, trustedOrganizationView{
			OrganizationID: organization.OrganizationID,
			Slug:           organization.Slug,
			Name:           organization.Name,
			DisplayName:    organization.DisplayName,
			Status:         string(organization.Status),
			OwnerUserID:    ownerUserIDs[organization.OrganizationID],
			MemberCount:    memberCounts[organization.OrganizationID],
			CreatedAt:      organization.CreatedAt,
			UpdatedAt:      organization.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"organizations": views,
		"total":         total,
		"page":          page,
		"page_size":     pageSize,
	})
}

func queryInt(c *gin.Context, key string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(c.Query(key)))
	if err != nil {
		return fallback
	}
	return value
}

func rolesJSONContains(raw string, role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	var roles []string
	if err := json.Unmarshal([]byte(raw), &roles); err != nil {
		return false
	}
	for _, item := range roles {
		if strings.EqualFold(strings.TrimSpace(item), role) {
			return true
		}
	}
	return false
}
