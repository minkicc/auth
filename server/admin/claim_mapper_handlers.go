package admin

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/iam"
)

const (
	securityAuditActionClaimMapperCreate = "claim_mapper_create"
	securityAuditActionClaimMapperUpdate = "claim_mapper_update"
	securityAuditActionClaimMapperDelete = "claim_mapper_delete"
)

type claimMapperPayload struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Enabled       *bool    `json:"enabled"`
	Claim         string   `json:"claim"`
	Value         string   `json:"value"`
	ValueFrom     string   `json:"value_from"`
	Events        []string `json:"events"`
	Clients       []string `json:"clients"`
	Organizations []string `json:"organizations"`
}

type claimMapperView struct {
	MapperID      string    `json:"mapper_id"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	Enabled       bool      `json:"enabled"`
	Claim         string    `json:"claim"`
	Value         string    `json:"value,omitempty"`
	ValueFrom     string    `json:"value_from,omitempty"`
	Events        []string  `json:"events"`
	Clients       []string  `json:"clients,omitempty"`
	Organizations []string  `json:"organizations,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (s *AdminServer) handleListClaimMappers(c *gin.Context) {
	var rules []iam.ClaimMapperRule
	if err := s.db.Order("created_at DESC, mapper_id DESC").Find(&rules).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	views := make([]claimMapperView, 0, len(rules))
	for _, rule := range rules {
		views = append(views, claimMapperViewFromRule(rule))
	}
	c.JSON(http.StatusOK, gin.H{"claim_mappers": views})
}

func (s *AdminServer) handleCreateClaimMapper(c *gin.Context) {
	actor := pluginAuditActor(c)
	var req claimMapperPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		s.appendSecurityAudit(securityAuditActionClaimMapperCreate, actor, false, err, map[string]string{"resource_type": "claim_mapper"})
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid claim mapper payload"})
		return
	}
	mapperID, err := iam.NewService(s.db).GenerateClaimMapperID()
	if err != nil {
		s.appendSecurityAudit(securityAuditActionClaimMapperCreate, actor, false, err, map[string]string{"resource_type": "claim_mapper"})
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	rule, err := claimMapperRuleFromPayload(mapperID, req, nil)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionClaimMapperCreate, actor, false, err, claimMapperAuditDetailsFromPayload(req, mapperID))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Create(&rule).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionClaimMapperCreate, actor, false, err, securityAuditDetailsForClaimMapperRule(rule))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	view := claimMapperViewFromRule(rule)
	s.appendSecurityAudit(securityAuditActionClaimMapperCreate, actor, true, nil, securityAuditDetailsForClaimMapperView(view))
	c.JSON(http.StatusCreated, gin.H{"claim_mapper": view})
}

func (s *AdminServer) handleUpdateClaimMapper(c *gin.Context) {
	actor := pluginAuditActor(c)
	current, ok := s.loadClaimMapper(c, c.Param("id"))
	if !ok {
		return
	}
	var req claimMapperPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		s.appendSecurityAudit(securityAuditActionClaimMapperUpdate, actor, false, err, securityAuditDetailsForClaimMapperRule(current))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid claim mapper payload"})
		return
	}
	rule, err := claimMapperRuleFromPayload(current.MapperID, req, &current)
	if err != nil {
		s.appendSecurityAudit(securityAuditActionClaimMapperUpdate, actor, false, err, claimMapperAuditDetailsFromPayload(req, current.MapperID))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.db.Save(&rule).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionClaimMapperUpdate, actor, false, err, securityAuditDetailsForClaimMapperRule(current))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	view := claimMapperViewFromRule(rule)
	s.appendSecurityAudit(securityAuditActionClaimMapperUpdate, actor, true, nil, securityAuditDetailsForClaimMapperView(view))
	c.JSON(http.StatusOK, gin.H{"claim_mapper": view})
}

func (s *AdminServer) handleDeleteClaimMapper(c *gin.Context) {
	actor := pluginAuditActor(c)
	rule, ok := s.loadClaimMapper(c, c.Param("id"))
	if !ok {
		return
	}
	if err := s.db.Delete(&iam.ClaimMapperRule{}, "mapper_id = ?", rule.MapperID).Error; err != nil {
		s.appendSecurityAudit(securityAuditActionClaimMapperDelete, actor, false, err, securityAuditDetailsForClaimMapperRule(rule))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.appendSecurityAudit(securityAuditActionClaimMapperDelete, actor, true, nil, securityAuditDetailsForClaimMapperRule(rule))
	c.JSON(http.StatusOK, gin.H{"message": "Claim mapper deleted successfully"})
}

func (s *AdminServer) loadClaimMapper(c *gin.Context, mapperID string) (iam.ClaimMapperRule, bool) {
	mapperID = strings.TrimSpace(mapperID)
	if mapperID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "claim mapper id is required"})
		return iam.ClaimMapperRule{}, false
	}
	var rule iam.ClaimMapperRule
	if err := s.db.First(&rule, "mapper_id = ?", mapperID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Claim mapper was not found"})
			return iam.ClaimMapperRule{}, false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return iam.ClaimMapperRule{}, false
	}
	return rule, true
}

func claimMapperRuleFromPayload(mapperID string, req claimMapperPayload, current *iam.ClaimMapperRule) (iam.ClaimMapperRule, error) {
	enabled := true
	if current != nil {
		enabled = current.Enabled
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return iam.ClaimMapperRuleFromSpec(mapperID, iam.ClaimMapperRuleSpec{
		Name:          req.Name,
		Description:   req.Description,
		Enabled:       enabled,
		Claim:         req.Claim,
		Value:         req.Value,
		ValueFrom:     req.ValueFrom,
		Events:        req.Events,
		Clients:       req.Clients,
		Organizations: req.Organizations,
	}, current)
}

func claimMapperViewFromRule(rule iam.ClaimMapperRule) claimMapperView {
	spec := iam.SpecFromClaimMapperRule(rule)
	return claimMapperView{
		MapperID:      rule.MapperID,
		Name:          spec.Name,
		Description:   spec.Description,
		Enabled:       spec.Enabled,
		Claim:         spec.Claim,
		Value:         spec.Value,
		ValueFrom:     spec.ValueFrom,
		Events:        spec.Events,
		Clients:       spec.Clients,
		Organizations: spec.Organizations,
		CreatedAt:     rule.CreatedAt,
		UpdatedAt:     rule.UpdatedAt,
	}
}

func securityAuditDetailsForClaimMapperRule(rule iam.ClaimMapperRule) map[string]string {
	return securityAuditDetailsForClaimMapperView(claimMapperViewFromRule(rule))
}

func securityAuditDetailsForClaimMapperView(view claimMapperView) map[string]string {
	details := map[string]string{
		"resource_type": "claim_mapper",
		"mapper_id":     view.MapperID,
		"name":          view.Name,
		"claim":         view.Claim,
		"enabled":       strconv.FormatBool(view.Enabled),
		"event_count":   strconv.Itoa(len(view.Events)),
	}
	if view.ValueFrom != "" {
		details["value_from"] = view.ValueFrom
	} else if view.Value != "" {
		details["value_mode"] = "static"
	}
	if len(view.Clients) > 0 {
		details["client_count"] = strconv.Itoa(len(view.Clients))
	}
	if len(view.Organizations) > 0 {
		details["organization_count"] = strconv.Itoa(len(view.Organizations))
	}
	return details
}

func claimMapperAuditDetailsFromPayload(req claimMapperPayload, mapperID string) map[string]string {
	details := map[string]string{
		"resource_type": "claim_mapper",
		"mapper_id":     strings.TrimSpace(mapperID),
		"name":          strings.TrimSpace(req.Name),
		"claim":         strings.TrimSpace(req.Claim),
	}
	if req.Enabled != nil {
		details["enabled"] = strconv.FormatBool(*req.Enabled)
	}
	if strings.TrimSpace(req.ValueFrom) != "" {
		details["value_from"] = strings.TrimSpace(req.ValueFrom)
	} else if strings.TrimSpace(req.Value) != "" {
		details["value_mode"] = "static"
	}
	return details
}
