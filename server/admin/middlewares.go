/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Logger middleware
func (s *AdminServer) loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		s.logger.Printf("[ADMIN] %s | %3d | %13v | %15s | %s",
			method, statusCode, latency, clientIP, path)
	}
}

// CORS middleware
func (s *AdminServer) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			// Use actual Origin from request instead of wildcard
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			// Allow requests with credentials
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// IP restriction middleware
func (s *AdminServer) ipRestrictionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(s.config.AllowedIPs) > 0 {
			clientIP := c.ClientIP()
			allowed := false

			for _, ip := range s.config.AllowedIPs {
				// 检查是否是通配符
				if ip == "*" {
					allowed = true
					break
				}

				// 检查是否是CIDR格式
				if strings.Contains(ip, "/") {
					_, ipnet, err := net.ParseCIDR(ip)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "无效的CIDR格式"})
						c.Abort()
						return
					}
					if ipnet.Contains(net.ParseIP(clientIP)) {
						allowed = true
						break
					}
				} else {
					// 普通IP地址匹配
					if ip == clientIP {
						allowed = true
						break
					}
				}
			}

			if !allowed {
				s.logger.Printf("Access request from %s denied", clientIP)
				c.JSON(http.StatusForbidden, gin.H{"error": "IP address not in allowed list"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// Authentication middleware
func (s *AdminServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		userID := session.Get(sessionUserIDKey)
		if userID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
			c.Abort()
			return
		}

		rolesJSON := session.Get(sessionRoleKey)
		if rolesJSON == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session is corrupted"})
			c.Abort()
			return
		}

		var roles []string
		if err := json.Unmarshal([]byte(rolesJSON.(string)), &roles); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse session"})
			c.Abort()
			return
		}

		userIDText, ok := userID.(string)
		if !ok || strings.TrimSpace(userIDText) == "" {
			session.Clear()
			_ = session.Save()
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session is corrupted"})
			c.Abort()
			return
		}
		if s == nil || s.accessController == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Admin access controller is not initialized"})
			c.Abort()
			return
		}
		isGlobalAdmin, sources, err := s.accessController.IsAdminUser(userIDText)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to evaluate admin access"})
			c.Abort()
			return
		}
		organizationAdminIDs, err := s.accessController.OrganizationAdminOrganizationIDs(userIDText)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to evaluate organization admin access"})
			c.Abort()
			return
		}
		if !isGlobalAdmin && len(organizationAdminIDs) == 0 {
			session.Clear()
			_ = session.Save()
			c.JSON(http.StatusForbidden, gin.H{"error": "Administrator access has been revoked"})
			c.Abort()
			return
		}
		roles = adminSessionRoles(isGlobalAdmin, len(organizationAdminIDs) > 0)

		c.Set("user_id", userIDText)
		if username := session.Get(sessionUsernameKey); username != nil {
			c.Set("username", username)
		}
		if nickname := session.Get(sessionNicknameKey); nickname != nil {
			c.Set("nickname", nickname)
		}
		c.Set("admin_sources", sources)
		c.Set("admin_access_checked", true)
		c.Set("admin_is_global", isGlobalAdmin)
		c.Set("organization_admin_ids", organizationAdminIDs)
		c.Set("roles", roles)

		c.Next()
	}
}

func (s *AdminServer) globalAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetBool("admin_is_global") {
			c.Next()
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Global administrator access is required"})
		c.Abort()
	}
}
