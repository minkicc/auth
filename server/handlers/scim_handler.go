package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
	"minki.cc/mkauth/server/iam"
)

const (
	scimUserSchema          = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema         = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimPatchSchema         = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimListResponseSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema         = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimProviderContextKey  = "scim_inbound_client"
	scimDefaultListPageSize = 100
	scimMaxListPageSize     = 200
)

var (
	scimFilterPattern = regexp.MustCompile(`(?i)^\s*([A-Za-z0-9_.]+)\s+eq\s+"?([^"]+)"?\s*$`)
	scimRolePattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

type SCIMHandler struct {
	db      *gorm.DB
	service *iam.Service
	clients []config.SCIMInboundConfig
}

type scimUserRequest struct {
	Schemas     []string         `json:"schemas,omitempty"`
	ID          string           `json:"id,omitempty"`
	ExternalID  string           `json:"externalId,omitempty"`
	UserName    string           `json:"userName,omitempty"`
	Active      *bool            `json:"active,omitempty"`
	DisplayName string           `json:"displayName,omitempty"`
	NickName    string           `json:"nickName,omitempty"`
	Name        scimName         `json:"name,omitempty"`
	Emails      []scimMultiValue `json:"emails,omitempty"`
	Roles       []scimMultiValue `json:"roles,omitempty"`
}

type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	MiddleName string `json:"middleName,omitempty"`
}

type scimMultiValue struct {
	Value   string `json:"value,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimUserResource struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id"`
	ExternalID  string           `json:"externalId,omitempty"`
	UserName    string           `json:"userName"`
	Active      bool             `json:"active"`
	DisplayName string           `json:"displayName,omitempty"`
	NickName    string           `json:"nickName,omitempty"`
	Name        scimName         `json:"name,omitempty"`
	Emails      []scimMultiValue `json:"emails,omitempty"`
	Roles       []scimMultiValue `json:"roles,omitempty"`
	Meta        scimMeta         `json:"meta"`
}

type scimMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
}

type scimListResponse struct {
	Schemas      []string           `json:"schemas"`
	TotalResults int                `json:"totalResults"`
	StartIndex   int                `json:"startIndex"`
	ItemsPerPage int                `json:"itemsPerPage"`
	Resources    []scimUserResource `json:"Resources"`
}

type scimPatchRequest struct {
	Schemas    []string        `json:"schemas,omitempty"`
	Operations []scimOperation `json:"Operations"`
}

type scimOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

type scimProvisionResult struct {
	User     auth.User
	Identity iam.ExternalIdentity
	Created  bool
}

func NewSCIMHandler(iamConfig config.IAMConfig, db *gorm.DB, service *iam.Service) *SCIMHandler {
	if db == nil || service == nil {
		return nil
	}
	clients := make([]config.SCIMInboundConfig, 0, len(iamConfig.SCIMInbound))
	for _, client := range iamConfig.SCIMInbound {
		client.Slug = strings.TrimSpace(client.Slug)
		client.Name = strings.TrimSpace(client.Name)
		client.OrganizationID = strings.TrimSpace(client.OrganizationID)
		client.BearerToken = strings.TrimSpace(client.BearerToken)
		client.BearerTokenHash = strings.TrimSpace(client.BearerTokenHash)
		if !client.Enabled || client.Slug == "" || client.OrganizationID == "" {
			continue
		}
		if client.BearerToken == "" && client.BearerTokenHash == "" {
			continue
		}
		clients = append(clients, client)
	}
	if len(clients) == 0 {
		return nil
	}
	return &SCIMHandler{db: db, service: service, clients: clients}
}

func (h *SCIMHandler) Enabled() bool {
	return h != nil && len(h.clients) > 0
}

func (h *SCIMHandler) RegisterRoutes(group *gin.RouterGroup) {
	if !h.Enabled() || group == nil {
		return
	}
	group.GET("/ServiceProviderConfig", h.handleServiceProviderConfig)
	group.GET("/ResourceTypes", h.handleResourceTypes)
	group.GET("/Schemas", h.handleSchemas)

	protected := group.Group("")
	protected.Use(h.authenticateSCIMClient())
	protected.GET("/Users", h.handleListSCIMUsers)
	protected.POST("/Users", h.handleCreateSCIMUser)
	protected.GET("/Users/:id", h.handleGetSCIMUser)
	protected.PUT("/Users/:id", h.handleReplaceSCIMUser)
	protected.PATCH("/Users/:id", h.handlePatchSCIMUser)
	protected.DELETE("/Users/:id", h.handleDeleteSCIMUser)
	protected.GET("/Groups", h.handleListSCIMGroups)
	protected.POST("/Groups", h.handleCreateSCIMGroup)
	protected.GET("/Groups/:id", h.handleGetSCIMGroup)
	protected.PUT("/Groups/:id", h.handleReplaceSCIMGroup)
	protected.PATCH("/Groups/:id", h.handlePatchSCIMGroup)
	protected.DELETE("/Groups/:id", h.handleDeleteSCIMGroup)
}

func (h *SCIMHandler) handleServiceProviderConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":                 gin.H{"supported": true},
		"bulk":                  gin.H{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                gin.H{"supported": true, "maxResults": scimMaxListPageSize},
		"changePassword":        gin.H{"supported": false},
		"sort":                  gin.H{"supported": false},
		"etag":                  gin.H{"supported": false},
		"authenticationSchemes": []gin.H{{"type": "oauthbearertoken", "name": "Bearer Token", "description": "SCIM bearer token"}},
	})
}

func (h *SCIMHandler) handleResourceTypes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{scimListResponseSchema},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources": []gin.H{{
			"id":          "User",
			"name":        "User",
			"endpoint":    "/Users",
			"schema":      scimUserSchema,
			"description": "MKAuth provisioned user",
		}, {
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"schema":      scimGroupSchema,
			"description": "MKAuth provisioned organization group",
		}},
	})
}

func (h *SCIMHandler) handleSchemas(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{scimListResponseSchema},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources": []gin.H{{
			"id":          scimUserSchema,
			"name":        "User",
			"description": "SCIM core user schema subset supported by MKAuth",
		}, {
			"id":          scimGroupSchema,
			"name":        "Group",
			"description": "SCIM core group schema subset supported by MKAuth",
		}},
	})
}

func (h *SCIMHandler) authenticateSCIMClient() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := scimBearerToken(c.GetHeader("Authorization"))
		if token == "" {
			c.Header("WWW-Authenticate", `Bearer realm="mkauth-scim"`)
			scimError(c, http.StatusUnauthorized, "", "missing bearer token")
			c.Abort()
			return
		}
		for _, client := range h.clients {
			if scimClientTokenMatches(client, token) {
				c.Set(scimProviderContextKey, client)
				c.Next()
				return
			}
		}
		c.Header("WWW-Authenticate", `Bearer realm="mkauth-scim"`)
		scimError(c, http.StatusUnauthorized, "", "invalid bearer token")
		c.Abort()
	}
}

func (h *SCIMHandler) handleListSCIMUsers(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	startIndex, count := scimPagination(c)
	query := h.db.Model(&iam.ExternalIdentity{}).
		Where("provider_type = ? AND provider_id = ?", iam.IdentityProviderTypeSCIM, client.Slug)
	query = applySCIMFilter(query, c.Query("filter"))

	var total int64
	if err := query.Count(&total).Error; err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}

	var identities []iam.ExternalIdentity
	if err := query.Order("created_at DESC").
		Offset(startIndex - 1).
		Limit(count).
		Find(&identities).Error; err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}

	resources, err := h.resourcesForIdentities(c, identities)
	if err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	c.JSON(http.StatusOK, scimListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: int(total),
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (h *SCIMHandler) handleCreateSCIMUser(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	var req scimUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		scimError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM user payload")
		return
	}
	result, err := h.provisionSCIMUser(client, req, "")
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	resource := h.userResource(c, result.User, result.Identity)
	c.Header("Location", resource.Meta.Location)
	status := http.StatusCreated
	if !result.Created {
		status = http.StatusOK
	}
	c.JSON(status, resource)
}

func (h *SCIMHandler) handleGetSCIMUser(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	user, identity, err := h.loadSCIMUserIdentity(client, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	c.JSON(http.StatusOK, h.userResource(c, user, identity))
}

func (h *SCIMHandler) handleReplaceSCIMUser(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	var req scimUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		scimError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM user payload")
		return
	}
	result, err := h.provisionSCIMUser(client, req, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	c.JSON(http.StatusOK, h.userResource(c, result.User, result.Identity))
}

func (h *SCIMHandler) handlePatchSCIMUser(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	user, identity, err := h.loadSCIMUserIdentity(client, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	var patch scimPatchRequest
	if err := c.ShouldBindJSON(&patch); err != nil {
		scimError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM patch payload")
		return
	}
	req := scimRequestFromResource(h.userResource(c, user, identity))
	if err := applySCIMPatch(&req, patch); err != nil {
		scimError(c, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	result, err := h.provisionSCIMUser(client, req, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	c.JSON(http.StatusOK, h.userResource(c, result.User, result.Identity))
}

func (h *SCIMHandler) handleDeleteSCIMUser(c *gin.Context) {
	client, ok := scimClientFromContext(c)
	if !ok {
		scimError(c, http.StatusUnauthorized, "", "missing scim client")
		return
	}
	user, identity, err := h.loadSCIMUserIdentity(client, c.Param("id"))
	if err != nil {
		h.writeProvisionError(c, err)
		return
	}
	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&auth.User{}).Where("user_id = ?", user.UserID).Updates(map[string]any{
			"status":     auth.UserStatusInactive,
			"updated_at": time.Now(),
		}).Error; err != nil {
			return err
		}
		return tx.Model(&iam.OrganizationMembership{}).
			Where("organization_id = ? AND user_id = ?", identity.OrganizationID, user.UserID).
			Updates(map[string]any{"status": iam.MembershipStatusDisabled, "updated_at": time.Now()}).Error
	}); err != nil {
		scimError(c, http.StatusInternalServerError, "", err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *SCIMHandler) provisionSCIMUser(client config.SCIMInboundConfig, req scimUserRequest, existingUserID string) (scimProvisionResult, error) {
	subject := scimSubject(req)
	if subject == "" {
		return scimProvisionResult{}, scimBadRequest("userName or externalId is required")
	}
	userName := strings.TrimSpace(req.UserName)
	if userName == "" {
		userName = subject
	}
	email := scimPrimaryEmail(req)
	displayName := scimDisplayName(req, userName)
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	roles, rolesJSON, err := normalizeSCIMRoles(req.Roles)
	if err != nil {
		return scimProvisionResult{}, scimBadRequest(err.Error())
	}
	profileJSON, err := marshalSCIMProfile(req, userName, email, displayName, roles)
	if err != nil {
		return scimProvisionResult{}, err
	}
	identityID, err := h.service.GenerateExternalIdentityID()
	if err != nil {
		return scimProvisionResult{}, err
	}

	var result scimProvisionResult
	err = h.db.Transaction(func(tx *gorm.DB) error {
		var identity iam.ExternalIdentity
		identityQuery := tx.Where("provider_type = ? AND provider_id = ?", iam.IdentityProviderTypeSCIM, client.Slug)
		var lookupErr error
		if strings.TrimSpace(existingUserID) != "" {
			lookupErr = identityQuery.Where("user_id = ?", strings.TrimSpace(existingUserID)).First(&identity).Error
		} else {
			lookupErr = identityQuery.Where("subject = ?", subject).First(&identity).Error
		}

		created := false
		var user auth.User
		now := time.Now()
		switch {
		case lookupErr == nil:
			if err := tx.First(&user, "user_id = ?", identity.UserID).Error; err != nil {
				return err
			}
		case errors.Is(lookupErr, gorm.ErrRecordNotFound) && strings.TrimSpace(existingUserID) == "":
			created = true
			newUser, err := h.newSCIMUser(tx, displayName, active, now)
			if err != nil {
				return err
			}
			user = newUser
			identity = iam.ExternalIdentity{
				ExternalIdentityID: identityID,
				ProviderType:       iam.IdentityProviderTypeSCIM,
				ProviderID:         client.Slug,
				Subject:            subject,
				UserID:             user.UserID,
				OrganizationID:     client.OrganizationID,
				Email:              email,
				EmailVerified:      email != "",
				DisplayName:        displayName,
				ProfileJSON:        profileJSON,
				CreatedAt:          now,
				UpdatedAt:          now,
			}
			if err := tx.Create(&user).Error; err != nil {
				return err
			}
			if err := tx.Create(&identity).Error; err != nil {
				return err
			}
		case errors.Is(lookupErr, gorm.ErrRecordNotFound):
			return gorm.ErrRecordNotFound
		default:
			return lookupErr
		}

		if !created {
			identity.Subject = subject
			identity.OrganizationID = client.OrganizationID
			identity.Email = email
			identity.EmailVerified = email != ""
			identity.DisplayName = displayName
			identity.ProfileJSON = profileJSON
			identity.UpdatedAt = now
			if err := tx.Save(&identity).Error; err != nil {
				return err
			}
			updates := map[string]any{
				"nickname":   truncateString(displayName, 50),
				"status":     scimUserStatus(active),
				"updated_at": now,
			}
			if err := tx.Model(&auth.User{}).Where("user_id = ?", identity.UserID).Updates(updates).Error; err != nil {
				return err
			}
			if err := tx.First(&user, "user_id = ?", identity.UserID).Error; err != nil {
				return err
			}
		}
		if err := upsertSCIMMembership(tx, client.OrganizationID, identity.UserID, active, rolesJSON, now); err != nil {
			return err
		}
		if err := h.recalculateSCIMGroupRoles(tx, client, []string{identity.UserID}, now); err != nil {
			return err
		}
		result = scimProvisionResult{User: user, Identity: identity, Created: created}
		return nil
	})
	return result, err
}

func (h *SCIMHandler) newSCIMUser(tx *gorm.DB, displayName string, active bool, now time.Time) (auth.User, error) {
	userID, err := auth.GenerateUserID(tx)
	if err != nil {
		return auth.User{}, err
	}
	randomPassword := make([]byte, 32)
	if _, err := rand.Read(randomPassword); err != nil {
		return auth.User{}, fmt.Errorf("generate scim user password: %w", err)
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(randomPassword, bcrypt.DefaultCost)
	if err != nil {
		return auth.User{}, fmt.Errorf("hash scim user password: %w", err)
	}
	return auth.User{
		UserID:       userID,
		Password:     string(hashedPassword),
		TokenVersion: auth.DefaultTokenVersion,
		Status:       scimUserStatus(active),
		Nickname:     truncateString(displayName, 50),
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func (h *SCIMHandler) loadSCIMUserIdentity(client config.SCIMInboundConfig, userID string) (auth.User, iam.ExternalIdentity, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return auth.User{}, iam.ExternalIdentity{}, gorm.ErrRecordNotFound
	}
	var identity iam.ExternalIdentity
	if err := h.db.First(&identity, "provider_type = ? AND provider_id = ? AND user_id = ?", iam.IdentityProviderTypeSCIM, client.Slug, userID).Error; err != nil {
		return auth.User{}, iam.ExternalIdentity{}, err
	}
	var user auth.User
	if err := h.db.First(&user, "user_id = ?", identity.UserID).Error; err != nil {
		return auth.User{}, iam.ExternalIdentity{}, err
	}
	return user, identity, nil
}

func (h *SCIMHandler) resourcesForIdentities(c *gin.Context, identities []iam.ExternalIdentity) ([]scimUserResource, error) {
	if len(identities) == 0 {
		return []scimUserResource{}, nil
	}
	userIDs := make([]string, 0, len(identities))
	for _, identity := range identities {
		userIDs = append(userIDs, identity.UserID)
	}
	var users []auth.User
	if err := h.db.Where("user_id IN ?", userIDs).Find(&users).Error; err != nil {
		return nil, err
	}
	byID := map[string]auth.User{}
	for _, user := range users {
		byID[user.UserID] = user
	}
	resources := make([]scimUserResource, 0, len(identities))
	for _, identity := range identities {
		user, ok := byID[identity.UserID]
		if !ok {
			continue
		}
		resources = append(resources, h.userResource(c, user, identity))
	}
	return resources, nil
}

func (h *SCIMHandler) userResource(c *gin.Context, user auth.User, identity iam.ExternalIdentity) scimUserResource {
	resource := scimUserResource{}
	if strings.TrimSpace(identity.ProfileJSON) != "" {
		_ = json.Unmarshal([]byte(identity.ProfileJSON), &resource)
	}
	if len(resource.Schemas) == 0 {
		resource.Schemas = []string{scimUserSchema}
	}
	resource.ID = user.UserID
	resource.ExternalID = identity.Subject
	if resource.UserName == "" {
		resource.UserName = firstNonEmpty(identity.Email, identity.Subject, user.UserID)
	}
	resource.Active = user.Status == auth.UserStatusActive
	resource.DisplayName = firstNonEmpty(resource.DisplayName, identity.DisplayName, user.Nickname)
	resource.NickName = firstNonEmpty(resource.NickName, user.Nickname)
	if len(resource.Emails) == 0 && identity.Email != "" {
		resource.Emails = []scimMultiValue{{Value: identity.Email, Type: "work", Primary: true}}
	}
	resource.Meta = scimMeta{
		ResourceType: "User",
		Created:      user.CreatedAt,
		LastModified: latestTime(user.UpdatedAt, identity.UpdatedAt),
		Location:     scimUserLocation(c, user.UserID),
	}
	return resource
}

func scimRequestFromResource(resource scimUserResource) scimUserRequest {
	active := resource.Active
	return scimUserRequest{
		Schemas:     resource.Schemas,
		ID:          resource.ID,
		ExternalID:  resource.ExternalID,
		UserName:    resource.UserName,
		Active:      &active,
		DisplayName: resource.DisplayName,
		NickName:    resource.NickName,
		Name:        resource.Name,
		Emails:      resource.Emails,
		Roles:       resource.Roles,
	}
}

func marshalSCIMProfile(req scimUserRequest, userName, email, displayName string, roles []string) (string, error) {
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	resource := scimUserResource{
		Schemas:     []string{scimUserSchema},
		ExternalID:  scimSubject(req),
		UserName:    userName,
		Active:      active,
		DisplayName: displayName,
		NickName:    firstNonEmpty(req.NickName, displayName),
		Name:        req.Name,
		Emails:      req.Emails,
		Roles:       req.Roles,
	}
	if len(resource.Emails) == 0 && email != "" {
		resource.Emails = []scimMultiValue{{Value: email, Type: "work", Primary: true}}
	}
	if len(resource.Roles) == 0 && len(roles) > 0 {
		for _, role := range roles {
			resource.Roles = append(resource.Roles, scimMultiValue{Value: role, Display: role})
		}
	}
	content, err := json.Marshal(resource)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func applySCIMPatch(req *scimUserRequest, patch scimPatchRequest) error {
	for _, op := range patch.Operations {
		opName := strings.ToLower(strings.TrimSpace(op.Op))
		if opName == "" {
			opName = "replace"
		}
		if opName != "replace" && opName != "add" {
			return fmt.Errorf("unsupported SCIM patch operation %q", op.Op)
		}
		path := strings.ToLower(strings.TrimSpace(op.Path))
		if path == "" {
			if values, ok := op.Value.(map[string]any); ok {
				applySCIMPatchMap(req, values)
				continue
			}
			return fmt.Errorf("patch path is required")
		}
		switch path {
		case "active":
			value, ok := boolFromAny(op.Value)
			if !ok {
				return fmt.Errorf("active must be boolean")
			}
			req.Active = &value
		case "displayname":
			req.DisplayName = strings.TrimSpace(fmt.Sprint(op.Value))
		case "nickname":
			req.NickName = strings.TrimSpace(fmt.Sprint(op.Value))
		case "username":
			req.UserName = strings.TrimSpace(fmt.Sprint(op.Value))
		case "externalid":
			req.ExternalID = strings.TrimSpace(fmt.Sprint(op.Value))
		case "name":
			name, err := scimNameFromAny(op.Value)
			if err != nil {
				return err
			}
			req.Name = name
		case "emails":
			emails, err := scimMultiValuesFromAny(op.Value)
			if err != nil {
				return err
			}
			req.Emails = emails
		case "roles":
			roles, err := scimMultiValuesFromAny(op.Value)
			if err != nil {
				return err
			}
			req.Roles = roles
		default:
			return fmt.Errorf("unsupported SCIM patch path %q", op.Path)
		}
	}
	return nil
}

func applySCIMPatchMap(req *scimUserRequest, values map[string]any) {
	for key, value := range values {
		switch strings.ToLower(key) {
		case "active":
			if parsed, ok := boolFromAny(value); ok {
				req.Active = &parsed
			}
		case "displayname":
			req.DisplayName = strings.TrimSpace(fmt.Sprint(value))
		case "nickname":
			req.NickName = strings.TrimSpace(fmt.Sprint(value))
		case "username":
			req.UserName = strings.TrimSpace(fmt.Sprint(value))
		case "externalid":
			req.ExternalID = strings.TrimSpace(fmt.Sprint(value))
		}
	}
}

func scimClientFromContext(c *gin.Context) (config.SCIMInboundConfig, bool) {
	value, ok := c.Get(scimProviderContextKey)
	if !ok {
		return config.SCIMInboundConfig{}, false
	}
	client, ok := value.(config.SCIMInboundConfig)
	return client, ok
}

func scimClientTokenMatches(client config.SCIMInboundConfig, token string) bool {
	if client.BearerTokenHash != "" && bcrypt.CompareHashAndPassword([]byte(client.BearerTokenHash), []byte(token)) == nil {
		return true
	}
	if client.BearerToken != "" && subtle.ConstantTimeCompare([]byte(client.BearerToken), []byte(token)) == 1 {
		return true
	}
	return false
}

func scimBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[7:])
}

func scimPagination(c *gin.Context) (int, int) {
	startIndex := 1
	count := scimDefaultListPageSize
	if raw := strings.TrimSpace(c.Query("startIndex")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			startIndex = value
		}
	}
	if raw := strings.TrimSpace(c.Query("count")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			count = value
		}
	}
	if count > scimMaxListPageSize {
		count = scimMaxListPageSize
	}
	return startIndex, count
}

func applySCIMFilter(query *gorm.DB, raw string) *gorm.DB {
	attr, value, ok := parseSCIMFilter(raw)
	if !ok {
		return query
	}
	switch attr {
	case "id":
		return query.Where("user_id = ?", value)
	case "externalid":
		return query.Where("subject = ?", value)
	case "username":
		return query.Where("subject = ? OR email = ?", value, strings.ToLower(value))
	case "emails.value", "email":
		return query.Where("email = ?", strings.ToLower(value))
	default:
		return query
	}
}

func parseSCIMFilter(raw string) (string, string, bool) {
	matches := scimFilterPattern.FindStringSubmatch(raw)
	if len(matches) != 3 {
		return "", "", false
	}
	attr := strings.ToLower(strings.TrimSpace(matches[1]))
	value := strings.TrimSpace(matches[2])
	if attr == "" || value == "" {
		return "", "", false
	}
	return attr, value, true
}

func scimSubject(req scimUserRequest) string {
	if value := strings.TrimSpace(req.ExternalID); value != "" {
		return value
	}
	return strings.TrimSpace(req.UserName)
}

func scimPrimaryEmail(req scimUserRequest) string {
	for _, email := range req.Emails {
		if email.Primary && strings.TrimSpace(email.Value) != "" {
			return normalizeSCIMEmail(email.Value)
		}
	}
	for _, email := range req.Emails {
		if strings.TrimSpace(email.Value) != "" {
			return normalizeSCIMEmail(email.Value)
		}
	}
	if strings.Contains(req.UserName, "@") {
		return normalizeSCIMEmail(req.UserName)
	}
	return ""
}

func normalizeSCIMEmail(email string) string {
	normalized, err := auth.NormalizeEmailAddress(email)
	if err != nil {
		return strings.TrimSpace(strings.ToLower(email))
	}
	return normalized
}

func scimDisplayName(req scimUserRequest, fallback string) string {
	return firstNonEmpty(req.DisplayName, req.NickName, req.Name.Formatted, strings.TrimSpace(req.Name.GivenName+" "+req.Name.FamilyName), fallback)
}

func normalizeSCIMRoles(raw []scimMultiValue) ([]string, string, error) {
	seen := map[string]struct{}{}
	roles := make([]string, 0, len(raw))
	for _, item := range raw {
		role := strings.TrimSpace(firstNonEmpty(item.Value, item.Display))
		if role == "" {
			continue
		}
		if !scimRolePattern.MatchString(role) {
			return nil, "", fmt.Errorf("role %q is invalid", role)
		}
		key := strings.ToLower(role)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roles = append(roles, role)
	}
	sort.Strings(roles)
	content, err := json.Marshal(roles)
	if err != nil {
		return nil, "", err
	}
	return roles, string(content), nil
}

func upsertSCIMMembership(tx *gorm.DB, organizationID, userID string, active bool, rolesJSON string, now time.Time) error {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil
	}
	status := iam.MembershipStatusActive
	if !active {
		status = iam.MembershipStatusDisabled
	}
	membership := iam.OrganizationMembership{
		OrganizationID: organizationID,
		UserID:         userID,
		Status:         status,
		RolesJSON:      rolesJSON,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "organization_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "roles_json", "updated_at"}),
	}).Create(&membership).Error
}

func scimUserStatus(active bool) auth.UserStatus {
	if active {
		return auth.UserStatusActive
	}
	return auth.UserStatusInactive
}

func boolFromAny(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
}

func scimNameFromAny(value any) (scimName, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return scimName{}, err
	}
	var name scimName
	if err := json.Unmarshal(content, &name); err != nil {
		return scimName{}, fmt.Errorf("name must be an object")
	}
	return name, nil
}

func scimMultiValuesFromAny(value any) ([]scimMultiValue, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var values []scimMultiValue
	if err := json.Unmarshal(content, &values); err == nil {
		return values, nil
	}
	var single scimMultiValue
	if err := json.Unmarshal(content, &single); err == nil && single.Value != "" {
		return []scimMultiValue{single}, nil
	}
	return nil, fmt.Errorf("value must be a SCIM multi-value array")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func latestTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func truncateString(value string, max int) string {
	value = strings.TrimSpace(value)
	if len([]rune(value)) <= max {
		return value
	}
	runes := []rune(value)
	return string(runes[:max])
}

func scimUserLocation(c *gin.Context, userID string) string {
	scheme := "http"
	if forwarded := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.Split(forwarded, ",")[0]
	} else if c.Request.TLS != nil {
		scheme = "https"
	}
	path := c.Request.URL.Path
	if idx := strings.Index(path, "/Users"); idx >= 0 {
		path = path[:idx] + "/Users/" + userID
	}
	return fmt.Sprintf("%s://%s%s", scheme, c.Request.Host, path)
}

type scimRequestError struct {
	detail string
}

func (e scimRequestError) Error() string { return e.detail }

func scimBadRequest(detail string) error { return scimRequestError{detail: detail} }

func (h *SCIMHandler) writeProvisionError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	var requestErr scimRequestError
	switch {
	case errors.As(err, &requestErr):
		scimError(c, http.StatusBadRequest, "invalidValue", requestErr.detail)
	case errors.Is(err, gorm.ErrRecordNotFound):
		scimError(c, http.StatusNotFound, "", "SCIM user was not found")
	default:
		scimError(c, http.StatusInternalServerError, "", err.Error())
	}
}

func scimError(c *gin.Context, status int, scimType, detail string) {
	body := gin.H{
		"schemas": []string{scimErrorSchema},
		"detail":  detail,
		"status":  strconv.Itoa(status),
	}
	if scimType != "" {
		body["scimType"] = scimType
	}
	c.JSON(status, body)
}
