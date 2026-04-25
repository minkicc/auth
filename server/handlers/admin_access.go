package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (h *AuthHandler) GetCurrentUserAdminAccess(c *gin.Context) {
	if h == nil || h.adminAccess == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled":  false,
			"is_admin": false,
		})
		return
	}

	userIDValue, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}

	userID, ok := userIDValue.(string)
	if !ok || strings.TrimSpace(userID) == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID type"})
		return
	}

	isAdmin, sources, err := h.adminAccess.IsAdminUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to evaluate admin access"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":   true,
		"is_admin":  isAdmin,
		"sources":   sources,
		"entry_url": h.adminEntryURL,
	})
}
