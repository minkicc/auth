/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package admin

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/oidc"
	"minki.cc/mkauth/server/plugins"
)

const (
	sessionUserIDKey   = "admin_user_id"
	sessionUsernameKey = "admin_username"
	sessionNicknameKey = "admin_nickname"
	sessionRoleKey     = "admin_roles"
	sessionSourceKey   = "admin_sources"
)

const ADMIN_ROUTER_PATH = config.ADMIN_ROUTER_PATH

func isAdminUIAssetRequest(path string) bool {
	if strings.HasPrefix(path, config.ADMIN_UI_BASE_PATH+"/assets/") {
		return true
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map":
		return strings.HasPrefix(path, config.ADMIN_UI_BASE_PATH+"/")
	default:
		return false
	}
}

// AdminServer Admin server
type AdminServer struct {
	config                  *config.AdminConfig
	publicBaseURL           string
	db                      *gorm.DB
	router                  *gin.Engine
	server                  *http.Server
	logger                  *log.Logger
	redis                   *auth.RedisStore
	sessionMgr              *auth.SessionManager
	plugins                 *plugins.Runtime
	oidcProvider            *oidc.Provider
	oidcStaticCfgs          []config.OIDCClientConfig
	accessController        *AccessController
	secretsEnabled          bool
	secretsFallbackKeyCount int
	enterpriseOIDC          *iam.EnterpriseOIDCManager
	enterpriseSAML          *iam.EnterpriseSAMLManager
	enterpriseLDAP          *iam.EnterpriseLDAPManager
	exportJobRetentionDays  int
	exportJobAutoCleanup    bool
	exportJobCleanupCancel  context.CancelFunc
	exportJobCleanupDone    chan struct{}
}

// NewAdminServer Create admin server
func NewAdminServer(cfg *config.Config, db *gorm.DB, logger *log.Logger, pluginRuntime *plugins.Runtime, oidcProvider *oidc.Provider, enterpriseOIDC *iam.EnterpriseOIDCManager, enterpriseSAML *iam.EnterpriseSAMLManager, enterpriseLDAP *iam.EnterpriseLDAPManager, accessController *AccessController, webFilePath string, port int) *AdminServer {
	if !cfg.Admin.Enabled {
		return nil
	}

	if cfg.Admin.HasLegacyAccounts() {
		logger.Println("Warning: auth_admin.accounts is deprecated and no longer used for administrator authentication; use auth_admin.user_ids and database-managed admins instead")
	}
	if accessController == nil {
		accessController = NewAccessController(&cfg.Admin, db)
	}

	// Initialize RedisStore
	redisAddr := cfg.Redis.GetRedisAddr()
	redisStore, err := auth.NewRedisStore(redisAddr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		logger.Printf("Warning: Failed to initialize Redis connection: %v", err)
		logger.Println("Some features may not work properly, such as session management")
	}

	// Initialize session manager
	sessionManager := auth.NewSessionManager(nil)
	if redisStore != nil {
		// Create session Redis storage
		sessionRedisStore := auth.NewSessionRedisStore(redisStore.GetClient())
		sessionManager = auth.NewSessionManager(sessionRedisStore)

		// Initialize session manager
		if err := sessionManager.Init(); err != nil {
			logger.Printf("Warning: Failed to initialize session manager: %v", err)
		} else {
			logger.Println("Session manager initialized successfully")
		}
	}

	// Create admin server
	server := &AdminServer{
		config:                  &cfg.Admin,
		publicBaseURL:           cfg.OIDC.Issuer,
		db:                      db,
		logger:                  logger,
		redis:                   redisStore,
		sessionMgr:              sessionManager,
		plugins:                 pluginRuntime,
		oidcProvider:            oidcProvider,
		oidcStaticCfgs:          append([]config.OIDCClientConfig(nil), cfg.OIDC.Clients...),
		accessController:        accessController,
		secretsEnabled:          len(cfg.Secrets.EffectiveEncryptionKeys()) > 0,
		secretsFallbackKeyCount: cfg.Secrets.FallbackKeyCount(),
		enterpriseOIDC:          enterpriseOIDC,
		enterpriseSAML:          enterpriseSAML,
		enterpriseLDAP:          enterpriseLDAP,
		exportJobRetentionDays:  cfg.Admin.SecurityAuditExportJobRetentionDaysOrDefault(),
		exportJobAutoCleanup:    cfg.Admin.SecurityAuditExportJobAutoCleanupEnabled(),
	}

	// Set Gin mode
	if gin.Mode() == gin.DebugMode {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(server.loggerMiddleware())
	router.Use(server.corsMiddleware())

	// Initialize session storage
	store := cookie.NewStore([]byte(cfg.Admin.SecretKey))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   cfg.Admin.SessionTTL * 60, // Convert to seconds
		HttpOnly: true,
		Secure:   cfg.Admin.RequireTLS,
	})
	router.Use(sessions.Sessions("kcauth_admin_session", store))

	// Add IP restriction middleware
	router.Use(server.ipRestrictionMiddleware())

	// Register routes
	server.registerRoutes(router, webFilePath)
	server.router = router

	// Create HTTP server
	server.server = &http.Server{
		Addr:    net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)),
		Handler: router,
	}

	return server
}

// Start Start admin server
func (s *AdminServer) Start() error {
	s.startSecurityAuditExportJobAutoCleanupLoop()
	s.logger.Printf("Admin server started on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

// Shutdown Shutdown admin server
func (s *AdminServer) Shutdown(ctx context.Context) error {
	s.stopSecurityAuditExportJobAutoCleanupLoop()
	// Close Redis connection
	if s.redis != nil {
		if err := s.redis.Close(); err != nil {
			s.logger.Printf("Failed to close Redis connection: %v", err)
		}
	}
	return s.server.Shutdown(ctx)
}

// Register routes
func (s *AdminServer) registerRoutes(r *gin.Engine, webFilePath string) {
	// Public routes
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// API routes group (requires authentication)
	admin := r.Group(ADMIN_ROUTER_PATH)
	// Login route
	admin.POST("/login", s.handleLogin)
	admin.POST("/session/bootstrap", s.handleLogin)

	admin.Use(s.authMiddleware())
	{
		admin.GET("/verify", s.handleVerifySession)
		admin.GET("/admins", s.handleListAdmins)
		admin.POST("/admins", s.handleCreateAdmin)
		admin.DELETE("/admins/:user_id", s.handleDeleteAdmin)

		// User statistics
		admin.GET("/stats", s.handleGetStats)

		// User list
		admin.GET("/users", s.handleGetUsers)

		// User activity
		admin.GET("/activity", s.handleGetActivity)

		// User session information
		admin.GET("/user/:id/sessions", s.handleGetUserSessions)
		admin.DELETE("/user/:id/sessions/:session_id", s.handleTerminateUserSession)
		admin.DELETE("/user/:id/sessions", s.handleTerminateAllUserSessions)

		// CIAM organization management
		admin.GET("/organizations", s.handleListOrganizations)
		admin.POST("/organizations", s.handleCreateOrganization)
		admin.GET("/organizations/:id", s.handleGetOrganization)
		admin.PATCH("/organizations/:id", s.handleUpdateOrganization)
		admin.GET("/organizations/:id/domains", s.handleListOrganizationDomains)
		admin.POST("/organizations/:id/domains", s.handleCreateOrganizationDomain)
		admin.PATCH("/organizations/:id/domains/:domain", s.handleUpdateOrganizationDomain)
		admin.DELETE("/organizations/:id/domains/:domain", s.handleDeleteOrganizationDomain)
		admin.GET("/organizations/:id/memberships", s.handleListOrganizationMemberships)
		admin.POST("/organizations/:id/memberships", s.handleUpsertOrganizationMembership)
		admin.PATCH("/organizations/:id/memberships/:user_id", s.handleUpdateOrganizationMembership)
		admin.DELETE("/organizations/:id/memberships/:user_id", s.handleDeleteOrganizationMembership)
		admin.GET("/organizations/:id/groups", s.handleListOrganizationGroups)
		admin.POST("/organizations/:id/groups", s.handleCreateOrganizationGroup)
		admin.GET("/organizations/:id/groups/:group_id", s.handleGetOrganizationGroup)
		admin.PATCH("/organizations/:id/groups/:group_id", s.handleUpdateOrganizationGroup)
		admin.DELETE("/organizations/:id/groups/:group_id", s.handleDeleteOrganizationGroup)
		admin.GET("/organizations/:id/roles", s.handleListOrganizationRoles)
		admin.POST("/organizations/:id/roles", s.handleCreateOrganizationRole)
		admin.PATCH("/organizations/:id/roles/:role_id", s.handleUpdateOrganizationRole)
		admin.DELETE("/organizations/:id/roles/:role_id", s.handleDeleteOrganizationRole)
		admin.POST("/organizations/:id/roles/:role_id/bindings", s.handleCreateOrganizationRoleBinding)
		admin.DELETE("/organizations/:id/roles/:role_id/bindings/:binding_id", s.handleDeleteOrganizationRoleBinding)
		admin.GET("/organizations/:id/identity-providers", s.handleListOrganizationIdentityProviders)
		admin.POST("/organizations/:id/identity-providers", s.handleCreateOrganizationIdentityProvider)
		admin.PATCH("/organizations/:id/identity-providers/:provider_id", s.handleUpdateOrganizationIdentityProvider)
		admin.DELETE("/organizations/:id/identity-providers/:provider_id", s.handleDeleteOrganizationIdentityProvider)
		admin.GET("/oidc/clients", s.handleListOIDCClients)
		admin.POST("/oidc/clients", s.handleCreateOIDCClient)
		admin.PATCH("/oidc/clients/:client_id", s.handleUpdateOIDCClient)
		admin.DELETE("/oidc/clients/:client_id", s.handleDeleteOIDCClient)
		admin.GET("/security/secrets/status", s.handleGetSecretsStatus)
		admin.GET("/security/audit", s.handleGetSecurityAudit)
		admin.GET("/security/audit/export", s.handleExportSecurityAudit)
		admin.GET("/security/audit/export-jobs", s.handleListSecurityAuditExportJobs)
		admin.POST("/security/audit/export-jobs", s.handleCreateSecurityAuditExportJob)
		admin.POST("/security/audit/export-jobs/cleanup", s.handleCleanupSecurityAuditExportJobs)
		admin.GET("/security/audit/export-jobs/:job_id", s.handleGetSecurityAuditExportJob)
		admin.DELETE("/security/audit/export-jobs/:job_id", s.handleDeleteSecurityAuditExportJob)
		admin.GET("/security/audit/export-jobs/:job_id/download", s.handleDownloadSecurityAuditExportJob)
		admin.GET("/security/secrets/audit", s.handleGetSecretsAudit)
		admin.GET("/security/secrets/audit/export", s.handleExportSecretsAudit)
		admin.GET("/security/secrets/audit/export-jobs", s.handleListSecretsAuditExportJobs)
		admin.POST("/security/secrets/audit/export-jobs", s.handleCreateSecretsAuditExportJob)
		admin.POST("/security/secrets/audit/export-jobs/cleanup", s.handleCleanupSecretsAuditExportJobs)
		admin.GET("/security/secrets/audit/export-jobs/:job_id", s.handleGetSecretsAuditExportJob)
		admin.DELETE("/security/secrets/audit/export-jobs/:job_id", s.handleDeleteSecretsAuditExportJob)
		admin.GET("/security/secrets/audit/export-jobs/:job_id/download", s.handleDownloadSecretsAuditExportJob)
		admin.POST("/security/secrets/reseal", s.handleResealManagedSecrets)

		// Plugin management
		admin.GET("/plugins", s.handleGetPlugins)
		admin.GET("/plugins/audit", s.handleGetPluginAudit)
		admin.GET("/plugins/backups", s.handleGetPluginBackups)
		admin.GET("/plugins/catalog", s.handleGetPluginCatalog)
		admin.GET("/plugins/:id/config", s.handleGetPluginConfig)
		admin.POST("/plugins/preview", s.handlePreviewPlugin)
		admin.POST("/plugins/install", s.handleInstallPlugin)
		admin.POST("/plugins/install-catalog", s.handleInstallPluginFromCatalog)
		admin.POST("/plugins/install-url", s.handleInstallPluginFromURL)
		admin.POST("/plugins/restore", s.handleRestorePluginBackup)
		admin.PATCH("/plugins/:id/config", s.handleUpdatePluginConfig)
		admin.PATCH("/plugins/:id", s.handleUpdatePlugin)
		admin.DELETE("/plugins/:id", s.handleDeletePlugin)

		// Logout
		admin.POST("/logout", s.handleLogout)
	}

	r.Use(func(c *gin.Context) {
		path := c.Request.URL.Path
		if path == config.ADMIN_UI_BASE_PATH || strings.HasPrefix(path, config.ADMIN_UI_BASE_PATH+"/") {
			c.Header("Cache-Control", "no-store")
		}
		c.Next()
	})

	// 添加静态文件服务
	r.Use(static.Serve(config.ADMIN_UI_BASE_PATH, static.LocalFile(webFilePath, false))) // 前端工程

	// All other routes redirect to admin UI entry point
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		// If it's an API request, return 404 error
		if path == ADMIN_ROUTER_PATH || strings.HasPrefix(path, ADMIN_ROUTER_PATH+"/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "auth endpoint not found"})
			return
		}
		if isAdminUIAssetRequest(path) {
			c.JSON(http.StatusNotFound, gin.H{"error": "admin asset not found"})
			return
		}
		if path == config.ADMIN_UI_BASE_PATH || strings.HasPrefix(path, config.ADMIN_UI_BASE_PATH+"/") {
			c.Header("Cache-Control", "no-store")
			c.File(webFilePath + "/index.html")
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "admin route not found"})
	})
}
