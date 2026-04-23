/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package admin

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/plugins"
)

const maxPluginPackageSize = 20 << 20

// Login handler
func (s *AdminServer) handleLogin(c *gin.Context) {
	var loginReq struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters"})
		return
	}

	// Validate username and password
	var matchedAccount *config.Account
	for _, account := range s.config.Accounts {
		if subtle.ConstantTimeCompare([]byte(account.Username), []byte(loginReq.Username)) == 1 {
			matchedAccount = &account
			break
		}
	}

	if matchedAccount == nil {
		s.logger.Printf("Login failed: Username %s does not exist", loginReq.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Validate password (assuming password is bcrypt hash)
	err := bcrypt.CompareHashAndPassword([]byte(matchedAccount.Password), []byte(loginReq.Password))
	if err != nil {
		s.logger.Printf("Login failed: User %s password error", loginReq.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Create session
	session := sessions.Default(c)

	// Convert roles to JSON string
	rolesJSON, err := json.Marshal(matchedAccount.Roles)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Store user information to session
	session.Set(sessionUserKey, matchedAccount.Username)
	session.Set(sessionRoleKey, string(rolesJSON))
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	s.logger.Printf("User %s login successful, IP: %s", matchedAccount.Username, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{
		"username": matchedAccount.Username,
		"roles":    matchedAccount.Roles,
	})
}

// Logout handler
func (s *AdminServer) handleLogout(c *gin.Context) {
	session := sessions.Default(c)

	session.Clear()
	session.Save()

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// Verify current admin session
func (s *AdminServer) handleVerifySession(c *gin.Context) {
	username, _ := c.Get("username")
	roles, _ := c.Get("roles")

	c.JSON(http.StatusOK, gin.H{
		"username": username,
		"roles":    roles,
	})
}

// Get user statistics
func (s *AdminServer) handleGetStats(c *gin.Context) {
	var stats struct {
		TotalUsers     int64 `json:"total_users"`
		ActiveUsers    int64 `json:"active_users"`
		InactiveUsers  int64 `json:"inactive_users"`
		LockedUsers    int64 `json:"locked_users"`
		BannedUsers    int64 `json:"banned_users"`
		NewToday       int64 `json:"new_today"`
		NewThisWeek    int64 `json:"new_this_week"`
		NewThisMonth   int64 `json:"new_this_month"`
		LoginToday     int64 `json:"login_today"`
		LoginThisWeek  int64 `json:"login_this_week"`
		LoginThisMonth int64 `json:"login_this_month"`
		EmailUsers     int64 `json:"email_users"`
		PhoneUsers     int64 `json:"phone_users"`
		SocialUsers    int64 `json:"social_users"`
		LocalUsers     int64 `json:"local_users"`
	}

	// Current time
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	weekStart := today.AddDate(0, 0, -int(now.Weekday()))
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	// Query user statistics
	s.db.Model(&auth.User{}).Count(&stats.TotalUsers)

	s.db.Model(&auth.User{}).Where("status = ?", auth.UserStatusActive).Count(&stats.ActiveUsers)
	s.db.Model(&auth.User{}).Where("status = ?", auth.UserStatusInactive).Count(&stats.InactiveUsers)
	s.db.Model(&auth.User{}).Where("status = ?", auth.UserStatusLocked).Count(&stats.LockedUsers)
	s.db.Model(&auth.User{}).Where("status = ?", auth.UserStatusBanned).Count(&stats.BannedUsers)

	s.db.Model(&auth.User{}).Where("created_at >= ?", today).Count(&stats.NewToday)
	s.db.Model(&auth.User{}).Where("created_at >= ?", weekStart).Count(&stats.NewThisWeek)
	s.db.Model(&auth.User{}).Where("created_at >= ?", monthStart).Count(&stats.NewThisMonth)

	s.db.Model(&auth.User{}).Where("last_login >= ?", today).Count(&stats.LoginToday)
	s.db.Model(&auth.User{}).Where("last_login >= ?", weekStart).Count(&stats.LoginThisWeek)
	s.db.Model(&auth.User{}).Where("last_login >= ?", monthStart).Count(&stats.LoginThisMonth)

	if s.db.Migrator().HasTable(&auth.EmailUser{}) {
		s.db.Model(&auth.EmailUser{}).Count(&stats.EmailUsers)
	}

	if s.db.Migrator().HasTable(&auth.PhoneUser{}) {
		s.db.Model(&auth.PhoneUser{}).Count(&stats.PhoneUsers)
	}

	socialUserIDs := make(map[string]struct{})
	if s.db.Migrator().HasTable(&auth.GoogleUser{}) {
		var googleUserIDs []string
		s.db.Model(&auth.GoogleUser{}).Distinct("user_id").Pluck("user_id", &googleUserIDs)
		for _, userID := range googleUserIDs {
			socialUserIDs[userID] = struct{}{}
		}
	}

	if s.db.Migrator().HasTable(&auth.WeixinUser{}) {
		var weixinUserIDs []string
		s.db.Model(&auth.WeixinUser{}).Distinct("user_id").Pluck("user_id", &weixinUserIDs)
		for _, userID := range weixinUserIDs {
			socialUserIDs[userID] = struct{}{}
		}
	}

	stats.SocialUsers = int64(len(socialUserIDs))
	stats.LocalUsers = stats.TotalUsers - stats.SocialUsers
	if stats.LocalUsers < 0 {
		stats.LocalUsers = 0
	}

	c.JSON(http.StatusOK, stats)
}

func (s *AdminServer) handleGetPlugins(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusOK, gin.H{"plugins": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"plugins": s.plugins.List()})
}

func (s *AdminServer) handleGetPluginCatalog(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusOK, gin.H{"plugins": []any{}})
		return
	}
	items, err := s.plugins.ListCatalogEntries(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if items == nil {
		c.JSON(http.StatusOK, gin.H{"plugins": []any{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"plugins": items})
}

func (s *AdminServer) handleGetPluginAudit(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusOK, gin.H{"audit": []any{}})
		return
	}
	limit := 100
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &limit); err != nil || limit < 1 {
			limit = 100
		}
	}
	if limit > 500 {
		limit = 500
	}
	events, err := s.plugins.ListAudit(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"audit": events})
}

func (s *AdminServer) handleGetPluginBackups(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusOK, gin.H{"backups": []any{}})
		return
	}
	limit := 100
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &limit); err != nil || limit < 1 {
			limit = 100
		}
	}
	if limit > 500 {
		limit = 500
	}
	backups, err := s.plugins.ListBackups(c.Query("plugin_id"), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"backups": backups})
}

func (s *AdminServer) handleInstallPlugin(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Plugin runtime is not enabled"})
		return
	}

	replace := strings.EqualFold(strings.TrimSpace(c.PostForm("replace")), "true")
	upload, err := c.FormFile("package")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Plugin package is required"})
		return
	}
	if !strings.HasSuffix(strings.ToLower(strings.TrimSpace(upload.Filename)), ".zip") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Plugin package must be a .zip file"})
		return
	}
	file, err := upload.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to open plugin package"})
		return
	}
	defer file.Close()

	content, err := io.ReadAll(io.LimitReader(file, maxPluginPackageSize+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read plugin package"})
		return
	}
	if len(content) > maxPluginPackageSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Plugin package is too large"})
		return
	}

	summary, err := s.plugins.InstallZipWithActor(upload.Filename, content, replace, pluginAuditActor(c))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin installed successfully",
		"plugin":  summary,
	})
}

func (s *AdminServer) handleInstallPluginFromCatalog(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Plugin runtime is not enabled"})
		return
	}

	var req struct {
		CatalogID string `json:"catalog_id"`
		PluginID  string `json:"plugin_id"`
		Replace   bool   `json:"replace"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.CatalogID) == "" || strings.TrimSpace(req.PluginID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "catalog_id and plugin_id are required"})
		return
	}

	ctx := plugins.ContextWithAuditActor(c.Request.Context(), pluginAuditActor(c))
	summary, err := s.plugins.InstallCatalogEntry(ctx, req.CatalogID, req.PluginID, req.Replace)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin installed successfully",
		"plugin":  summary,
	})
}

func (s *AdminServer) handleInstallPluginFromURL(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Plugin runtime is not enabled"})
		return
	}

	var req struct {
		URL           string `json:"url"`
		Replace       bool   `json:"replace"`
		PackageSHA256 string `json:"package_sha256"`
		Source        string `json:"source"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.URL) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url is required"})
		return
	}

	ctx := plugins.ContextWithAuditActor(c.Request.Context(), pluginAuditActor(c))
	summary, err := s.plugins.InstallURL(ctx, req.URL, req.PackageSHA256, req.Source, req.Replace)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin installed successfully",
		"plugin":  summary,
	})
}

func (s *AdminServer) handleUpdatePlugin(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Plugin runtime is not enabled"})
		return
	}

	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled is required"})
		return
	}

	summary, err := s.plugins.SetEnabledWithActor(c.Param("id"), *req.Enabled, pluginAuditActor(c))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin updated successfully",
		"plugin":  summary,
	})
}

func (s *AdminServer) handleDeletePlugin(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Plugin runtime is not enabled"})
		return
	}
	if err := s.plugins.UninstallWithActor(c.Param("id"), pluginAuditActor(c)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Plugin deleted successfully"})
}

func (s *AdminServer) handleRestorePluginBackup(c *gin.Context) {
	if s.plugins == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Plugin runtime is not enabled"})
		return
	}

	var req struct {
		BackupID string `json:"backup_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.BackupID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "backup_id is required"})
		return
	}

	summary, err := s.plugins.RestoreBackupWithActor(req.BackupID, pluginAuditActor(c))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin restored successfully",
		"plugin":  summary,
	})
}

func pluginAuditActor(c *gin.Context) plugins.AuditActor {
	actorID := ""
	if username, ok := c.Get("username"); ok && username != nil {
		if value, ok := username.(string); ok {
			actorID = value
		} else {
			actorID = fmt.Sprint(username)
		}
	}
	return plugins.AuditActor{
		ID:        actorID,
		IP:        c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
	}
}

// Get user list
func (s *AdminServer) handleGetUsers(c *gin.Context) {
	// Pagination parameters
	page := 1
	if pageStr := c.Query("page"); pageStr != "" {
		fmt.Sscanf(pageStr, "%d", &page)
		if page < 1 {
			page = 1
		}
	}

	pageSize := 20
	if sizeStr := c.Query("size"); sizeStr != "" {
		fmt.Sscanf(sizeStr, "%d", &pageSize)
		if pageSize < 1 || pageSize > 100 {
			pageSize = 20
		}
	}

	// Filter parameters
	status := c.Query("status")
	provider := c.Query("provider")
	search := c.Query("search")

	// Build query conditions
	query := s.db.Model(&auth.User{})

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if provider != "" {
		// If auth.User does not have provider field, this part may need adjustment
		// query = query.Where("provider = ?", provider)
	}

	if search != "" {
		searchTerm := "%" + search + "%"
		matchedUserIDs := findUserIDsByLoginIdentifier(s.db, searchTerm)
		if len(matchedUserIDs) > 0 {
			query = query.Where("user_id LIKE ? OR nickname LIKE ? OR user_id IN ?", searchTerm, searchTerm, matchedUserIDs)
		} else {
			query = query.Where("user_id LIKE ? OR nickname LIKE ?", searchTerm, searchTerm)
		}
	}

	// Total result count
	var total int64
	query.Count(&total)

	// Paginated query
	var users []auth.User
	offset := (page - 1) * pageSize

	err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&users).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query user list"})
		return
	}

	// Remove sensitive information
	for i := range users {
		users[i].Password = ""
		// Delete non-existent TwoFactorSecret field, according to actual User structure definition
		// users[i].TwoFactorSecret = ""
	}
	attachAccountUsernames(s.db, users)

	c.JSON(http.StatusOK, gin.H{
		"users":      users,
		"total":      total,
		"page":       page,
		"page_size":  pageSize,
		"total_page": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}

func attachAccountUsernames(db *gorm.DB, users []auth.User) {
	if db == nil || len(users) == 0 || !db.Migrator().HasTable(&auth.AccountUser{}) {
		return
	}

	userIDs := make([]string, 0, len(users))
	for _, user := range users {
		if user.UserID != "" {
			userIDs = append(userIDs, user.UserID)
		}
	}
	if len(userIDs) == 0 {
		return
	}

	var accountUsers []auth.AccountUser
	if err := db.Where("user_id IN ?", userIDs).Find(&accountUsers).Error; err != nil {
		return
	}

	usernameByUserID := make(map[string]string, len(accountUsers))
	for _, accountUser := range accountUsers {
		usernameByUserID[accountUser.UserID] = accountUser.Username
	}
	for i := range users {
		users[i].Username = usernameByUserID[users[i].UserID]
	}
}

func findUserIDsByLoginIdentifier(db *gorm.DB, searchTerm string) []string {
	if db == nil {
		return nil
	}

	seen := make(map[string]struct{})
	addUserIDs := func(ids []string) {
		for _, id := range ids {
			if id != "" {
				seen[id] = struct{}{}
			}
		}
	}

	if db.Migrator().HasTable(&auth.AccountUser{}) {
		var ids []string
		if err := db.Model(&auth.AccountUser{}).Where("username LIKE ?", searchTerm).Pluck("user_id", &ids).Error; err == nil {
			addUserIDs(ids)
		}
	}
	if db.Migrator().HasTable(&auth.EmailUser{}) {
		var ids []string
		if err := db.Model(&auth.EmailUser{}).Where("email LIKE ?", searchTerm).Pluck("user_id", &ids).Error; err == nil {
			addUserIDs(ids)
		}
	}
	if db.Migrator().HasTable(&auth.PhoneUser{}) {
		var ids []string
		if err := db.Model(&auth.PhoneUser{}).Where("phone LIKE ?", searchTerm).Pluck("user_id", &ids).Error; err == nil {
			addUserIDs(ids)
		}
	}

	userIDs := make([]string, 0, len(seen))
	for id := range seen {
		userIDs = append(userIDs, id)
	}
	return userIDs
}

// Get user activity
func (s *AdminServer) handleGetActivity(c *gin.Context) {
	// Date range parameters
	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		fmt.Sscanf(daysStr, "%d", &days)
		if days < 1 || days > 90 {
			days = 30
		}
	}

	// Calculate start date
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -days)

	// Prepare return result
	type DailyActivity struct {
		Date           string `json:"date"`
		NewUsers       int64  `json:"new_users"`
		ActiveUsers    int64  `json:"active_users"`
		LoginAttempts  int64  `json:"login_attempts"`
		SuccessfulAuth int64  `json:"successful_auth"`
		FailedAuth     int64  `json:"failed_auth"`
	}

	result := make([]DailyActivity, 0, days)

	// Calculate daily data
	current := startDate
	for current.Before(endDate) || current.Equal(endDate) {
		currentEnd := current.AddDate(0, 0, 1)

		var activity DailyActivity
		activity.Date = current.Format("2006-01-02")

		// New users
		s.db.Model(&auth.User{}).Where("created_at >= ? AND created_at < ?", current, currentEnd).Count(&activity.NewUsers)

		// Active users (users with login activity)
		s.db.Model(&auth.User{}).Where("last_login >= ? AND last_login < ?", current, currentEnd).Count(&activity.ActiveUsers)

		// Login attempts - may need adjustment LoginAttempt structure
		if s.db.Migrator().HasTable(&auth.LoginAttempt{}) {
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ?", current, currentEnd).Count(&activity.LoginAttempts)

			// Successful authentication
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ? AND success = ?", current, currentEnd, true).Count(&activity.SuccessfulAuth)

			// Failed authentication
			s.db.Model(&auth.LoginAttempt{}).Where("created_at >= ? AND created_at < ? AND success = ?", current, currentEnd, false).Count(&activity.FailedAuth)
		} else {
			// If there is no LoginAttempt table, give default value
			activity.LoginAttempts = 0
			activity.SuccessfulAuth = 0
			activity.FailedAuth = 0
		}

		result = append(result, activity)
		current = currentEnd
	}

	c.JSON(http.StatusOK, result)
}

// Get user session list
func (s *AdminServer) handleGetUserSessions(c *gin.Context) {
	userID := c.Param("id")

	// Parameter validation
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID cannot be empty"})
		return
	}

	s.logger.Printf("Get user %s session list", userID)

	// Create session manager
	sessionManager := s.sessionMgr

	// Use optimized method to get sessions
	sessions, err := sessionManager.GetUserSessions(userID)
	if err != nil {
		s.logger.Printf("Failed to get user sessions: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query sessions"})
		return
	}

	// Ensure sessions are not null
	if sessions == nil {
		sessions = []*auth.Session{}
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
	})
}

// Terminate specific user session
func (s *AdminServer) handleTerminateUserSession(c *gin.Context) {
	userID := c.Param("id")
	sessionID := c.Param("session_id")

	// Parameter validation
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID cannot be empty"})
		return
	}

	// Create session manager
	sessionManager := s.sessionMgr

	// Delete session from Redis
	if err := sessionManager.DeleteSession(userID, sessionID); err != nil {
		s.logger.Printf("Failed to terminate session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to terminate session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session successfully terminated"})
}

// Terminate all user sessions
func (s *AdminServer) handleTerminateAllUserSessions(c *gin.Context) {
	userID := c.Param("id")

	// Parameter validation
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID cannot be empty"})
		return
	}

	s.logger.Printf("Preparing to terminate all sessions for user %s", userID)

	// Create session manager
	sessionManager := s.sessionMgr

	// Terminate all regular sessions
	deletedCount, err := sessionManager.DeleteUserSessions(userID)
	if err != nil {
		s.logger.Printf("Failed to terminate user sessions: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to terminate regular sessions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "All user sessions successfully terminated",
		"user_id":       userID,
		"deleted_count": len(deletedCount),
	})
}
