package admin

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"minki.cc/mkauth/server/iam"
	"minki.cc/mkauth/server/oidc"
	"minki.cc/mkauth/server/secureconfig"
)

type secretsStatusView struct {
	Enabled                      bool  `json:"enabled"`
	FallbackKeyCount             int   `json:"fallback_key_count"`
	ManagedOIDCClientCount       int64 `json:"managed_oidc_client_count"`
	ManagedIdentityProviderCount int64 `json:"managed_identity_provider_count"`
}

type secretsResealResult struct {
	OIDCClients       int `json:"oidc_clients"`
	IdentityProviders int `json:"identity_providers"`
	OIDCProviders     int `json:"oidc_providers"`
	SAMLProviders     int `json:"saml_providers"`
	LDAPProviders     int `json:"ldap_providers"`
}

func (s *AdminServer) handleGetSecretsStatus(c *gin.Context) {
	status, err := s.secretsStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": status})
}

func (s *AdminServer) handleGetSecurityAudit(c *gin.Context) {
	options, err := securityAuditListOptionsFromRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := s.listSecurityAuditWithOptions(options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *AdminServer) handleExportSecurityAudit(c *gin.Context) {
	options, err := securityAuditListOptionsFromRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	events, total, truncated, err := s.listSecurityAuditEventsForExport(options, securityAuditExportMaxRows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	content, err := buildSecurityAuditCSV(events)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	filename := fmt.Sprintf("security-audit-%s.csv", time.Now().UTC().Format("20060102-150405"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	c.Header("X-MKAuth-Export-Total", strconv.FormatInt(total, 10))
	c.Header("X-MKAuth-Export-Limit", strconv.Itoa(securityAuditExportMaxRows))
	if truncated {
		c.Header("X-MKAuth-Export-Truncated", "true")
	}
	c.String(http.StatusOK, content)
}

func (s *AdminServer) handleCreateSecurityAuditExportJob(c *gin.Context) {
	var request securityAuditExportJobRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid security audit export payload"})
			return
		}
	}
	options, err := securityAuditListOptionsFromExportRequest(request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	request = securityAuditExportJobRequestFromOptions(options)
	record, err := s.createSecurityAuditExportJob(request, pluginAuditActor(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	go s.processSecurityAuditExportJob(record.JobID, options)
	view, err := securityAuditExportJobViewFromRecord(record)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"message": "security audit export job created",
		"job":     view,
	})
}

func (s *AdminServer) handleListSecurityAuditExportJobs(c *gin.Context) {
	options, err := securityAuditExportJobListOptionsFromRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := s.listSecurityAuditExportJobs(options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (s *AdminServer) handleDeleteSecurityAuditExportJob(c *gin.Context) {
	err := s.deleteSecurityAuditExportJob(c.Param("job_id"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "security audit export job not found"})
			return
		}
		if strings.Contains(err.Error(), "still running") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "security audit export job deleted"})
}

func (s *AdminServer) handleCleanupSecurityAuditExportJobs(c *gin.Context) {
	var request securityAuditExportJobCleanupRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid security audit export cleanup payload"})
			return
		}
	}
	result, err := s.cleanupSecurityAuditExportJobs(request)
	if err != nil {
		if strings.Contains(err.Error(), "status must be") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "security audit export jobs cleaned up",
		"result":  result,
	})
}

func (s *AdminServer) handleGetSecurityAuditExportJob(c *gin.Context) {
	record, err := s.getSecurityAuditExportJob(c.Param("job_id"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "security audit export job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	view, err := securityAuditExportJobViewFromRecord(record)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"job": view})
}

func (s *AdminServer) handleDownloadSecurityAuditExportJob(c *gin.Context) {
	record, err := s.getSecurityAuditExportJob(c.Param("job_id"))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "security audit export job not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	switch record.Status {
	case securityAuditExportJobStatusPending, securityAuditExportJobStatusRunning:
		c.JSON(http.StatusConflict, gin.H{"error": "security audit export job is still running"})
		return
	case securityAuditExportJobStatusFailed:
		c.JSON(http.StatusConflict, gin.H{"error": record.Error})
		return
	}
	if strings.TrimSpace(record.Content) == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "security audit export content is not available"})
		return
	}
	c.Header("Content-Type", record.ContentType)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", record.FileName))
	c.Header("X-MKAuth-Export-Total", strconv.FormatInt(record.TotalCount, 10))
	c.Header("X-MKAuth-Export-Limit", strconv.Itoa(securityAuditExportMaxRows))
	if record.Truncated {
		c.Header("X-MKAuth-Export-Truncated", "true")
	}
	c.String(http.StatusOK, record.Content)
}

func (s *AdminServer) handleGetSecretsAudit(c *gin.Context) {
	s.handleGetSecurityAudit(c)
}

func (s *AdminServer) handleExportSecretsAudit(c *gin.Context) {
	s.handleExportSecurityAudit(c)
}

func (s *AdminServer) handleCreateSecretsAuditExportJob(c *gin.Context) {
	s.handleCreateSecurityAuditExportJob(c)
}

func (s *AdminServer) handleListSecretsAuditExportJobs(c *gin.Context) {
	s.handleListSecurityAuditExportJobs(c)
}

func (s *AdminServer) handleCleanupSecretsAuditExportJobs(c *gin.Context) {
	s.handleCleanupSecurityAuditExportJobs(c)
}

func (s *AdminServer) handleGetSecretsAuditExportJob(c *gin.Context) {
	s.handleGetSecurityAuditExportJob(c)
}

func (s *AdminServer) handleDeleteSecretsAuditExportJob(c *gin.Context) {
	s.handleDeleteSecurityAuditExportJob(c)
}

func (s *AdminServer) handleDownloadSecretsAuditExportJob(c *gin.Context) {
	s.handleDownloadSecurityAuditExportJob(c)
}

func (s *AdminServer) handleResealManagedSecrets(c *gin.Context) {
	actor := pluginAuditActor(c)
	if !s.secretsEnabled || !secureconfig.Enabled() {
		err := fmt.Errorf("secrets encryption is not enabled")
		s.appendSecurityAudit(securityAuditActionSecretsReseal, actor, false, err, map[string]string{
			"reason": "encryption_disabled",
		})
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	result, err := s.resealManagedSecrets()
	if err != nil {
		s.appendSecurityAudit(securityAuditActionSecretsReseal, actor, false, err, map[string]string{
			"stage": "reseal_transaction",
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadOIDCClients(); err != nil {
		s.appendSecurityAudit(securityAuditActionSecretsReseal, actor, false, err, map[string]string{
			"stage": "reload_oidc_clients",
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.reloadEnterpriseIdentityProviders(); err != nil {
		s.appendSecurityAudit(securityAuditActionSecretsReseal, actor, false, err, map[string]string{
			"stage": "reload_enterprise_identity_providers",
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.appendSecurityAudit(securityAuditActionSecretsReseal, actor, true, nil, securityAuditDetailsForReseal(result, s.secretsFallbackKeyCount))
	c.JSON(http.StatusOK, gin.H{
		"message": "managed secrets resealed successfully",
		"result":  result,
	})
}

func (s *AdminServer) secretsStatus() (secretsStatusView, error) {
	status := secretsStatusView{
		Enabled:          s.secretsEnabled && secureconfig.Enabled(),
		FallbackKeyCount: s.secretsFallbackKeyCount,
	}
	if s == nil || s.db == nil {
		return status, nil
	}
	if err := s.db.Model(&oidc.ClientRecord{}).Count(&status.ManagedOIDCClientCount).Error; err != nil {
		return secretsStatusView{}, err
	}
	if err := s.db.Model(&iam.OrganizationIdentityProvider{}).Count(&status.ManagedIdentityProviderCount).Error; err != nil {
		return secretsStatusView{}, err
	}
	return status, nil
}

func (s *AdminServer) resealManagedSecrets() (secretsResealResult, error) {
	if s == nil || s.db == nil {
		return secretsResealResult{}, fmt.Errorf("admin server requires database")
	}
	result := secretsResealResult{}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var clientRecords []oidc.ClientRecord
		if err := tx.Order("created_at ASC").Find(&clientRecords).Error; err != nil {
			return err
		}
		for _, record := range clientRecords {
			clientCfg, err := oidc.ClientConfigFromRecord(record)
			if err != nil {
				return err
			}
			updatedRecord, err := oidc.ClientRecordFromConfig(clientCfg, record.Enabled)
			if err != nil {
				return err
			}
			if err := tx.Model(&oidc.ClientRecord{}).
				Where("client_id = ?", record.ClientID).
				Updates(map[string]any{
					"name":        updatedRecord.Name,
					"enabled":     updatedRecord.Enabled,
					"config_json": updatedRecord.ConfigJSON,
				}).Error; err != nil {
				return err
			}
			result.OIDCClients++
		}

		var providerRecords []iam.OrganizationIdentityProvider
		if err := tx.Order("created_at ASC").Find(&providerRecords).Error; err != nil {
			return err
		}
		for _, record := range providerRecords {
			encoded, providerType, err := resealedIdentityProviderConfig(record)
			if err != nil {
				return err
			}
			if err := tx.Model(&iam.OrganizationIdentityProvider{}).
				Where("identity_provider_id = ?", record.IdentityProviderID).
				Update("config_json", encoded).Error; err != nil {
				return err
			}
			result.IdentityProviders++
			switch providerType {
			case iam.IdentityProviderTypeOIDC:
				result.OIDCProviders++
			case iam.IdentityProviderTypeSAML:
				result.SAMLProviders++
			case iam.IdentityProviderTypeLDAP:
				result.LDAPProviders++
			}
		}
		return nil
	})
	return result, err
}

func resealedIdentityProviderConfig(record iam.OrganizationIdentityProvider) (string, iam.IdentityProviderType, error) {
	switch record.ProviderType {
	case iam.IdentityProviderTypeOIDC:
		providerConfig, err := decodeStoredEnterpriseOIDCConfig(record)
		if err != nil {
			return "", record.ProviderType, err
		}
		encoded, err := encodeStoredEnterpriseOIDCConfig(providerConfig)
		return encoded, record.ProviderType, err
	case iam.IdentityProviderTypeSAML:
		providerConfig, err := decodeStoredEnterpriseSAMLConfig(record)
		if err != nil {
			return "", record.ProviderType, err
		}
		encoded, err := encodeStoredEnterpriseSAMLConfig(providerConfig)
		return encoded, record.ProviderType, err
	case iam.IdentityProviderTypeLDAP:
		providerConfig, err := decodeStoredEnterpriseLDAPConfig(record)
		if err != nil {
			return "", record.ProviderType, err
		}
		encoded, err := encodeStoredEnterpriseLDAPConfig(providerConfig)
		return encoded, record.ProviderType, err
	default:
		return record.ConfigJSON, record.ProviderType, nil
	}
}

func securityAuditListOptionsFromRequest(c *gin.Context) (securityAuditListOptions, error) {
	options := securityAuditListOptions{
		Page: 1,
		Size: 20,
	}
	if rawPage := strings.TrimSpace(c.Query("page")); rawPage != "" {
		page, err := strconv.Atoi(rawPage)
		if err != nil || page <= 0 {
			return securityAuditListOptions{}, fmt.Errorf("page must be a positive integer")
		}
		options.Page = page
	}
	if rawSize := strings.TrimSpace(c.Query("size")); rawSize != "" {
		size, err := strconv.Atoi(rawSize)
		if err != nil || size <= 0 {
			return securityAuditListOptions{}, fmt.Errorf("size must be a positive integer")
		}
		options.Size = size
	} else if rawLimit := strings.TrimSpace(c.Query("limit")); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit <= 0 {
			return securityAuditListOptions{}, fmt.Errorf("limit must be a positive integer")
		}
		options.Size = limit
		options.Page = 1
	}
	options.Action = strings.TrimSpace(c.Query("action"))
	options.ResourceType = strings.TrimSpace(strings.ToLower(c.Query("resource_type")))
	options.ClientID = strings.TrimSpace(c.Query("client_id"))
	options.ProviderID = strings.TrimSpace(c.Query("provider_id"))
	options.OrganizationID = strings.TrimSpace(c.Query("organization_id"))
	options.ActorID = strings.TrimSpace(c.Query("actor_id"))
	options.Query = strings.TrimSpace(c.Query("query"))
	if rawTimeFrom := strings.TrimSpace(c.Query("time_from")); rawTimeFrom != "" {
		parsed, err := parseSecurityAuditTime(rawTimeFrom, false)
		if err != nil {
			return securityAuditListOptions{}, fmt.Errorf("time_from must be RFC3339 or YYYY-MM-DD")
		}
		options.TimeFrom = &parsed
	}
	if rawTimeTo := strings.TrimSpace(c.Query("time_to")); rawTimeTo != "" {
		parsed, err := parseSecurityAuditTime(rawTimeTo, true)
		if err != nil {
			return securityAuditListOptions{}, fmt.Errorf("time_to must be RFC3339 or YYYY-MM-DD")
		}
		options.TimeTo = &parsed
	}
	if options.TimeFrom != nil && options.TimeTo != nil && options.TimeFrom.After(*options.TimeTo) {
		return securityAuditListOptions{}, fmt.Errorf("time_from must be earlier than or equal to time_to")
	}
	if rawSuccess := strings.TrimSpace(strings.ToLower(c.Query("success"))); rawSuccess != "" {
		switch rawSuccess {
		case "1", "true", "success":
			success := true
			options.Success = &success
		case "0", "false", "failure", "failed":
			success := false
			options.Success = &success
		default:
			return securityAuditListOptions{}, fmt.Errorf("success must be true or false")
		}
	}
	return options, nil
}

func securityAuditExportJobListOptionsFromRequest(c *gin.Context) (securityAuditExportJobListOptions, error) {
	options := securityAuditExportJobListOptions{
		Page: 1,
		Size: 10,
	}
	if rawPage := strings.TrimSpace(c.Query("page")); rawPage != "" {
		page, err := strconv.Atoi(rawPage)
		if err != nil || page <= 0 {
			return securityAuditExportJobListOptions{}, fmt.Errorf("page must be a positive integer")
		}
		options.Page = page
	}
	if rawSize := strings.TrimSpace(c.Query("size")); rawSize != "" {
		size, err := strconv.Atoi(rawSize)
		if err != nil || size <= 0 {
			return securityAuditExportJobListOptions{}, fmt.Errorf("size must be a positive integer")
		}
		options.Size = size
	}
	options.Status = strings.TrimSpace(strings.ToLower(c.Query("status")))
	options.OrganizationID = strings.TrimSpace(c.Query("organization_id"))
	return options, nil
}

func parseSecurityAuditTime(raw string, endOfDay bool) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			if layout == "2006-01-02" {
				if endOfDay {
					parsed = parsed.Add(24*time.Hour - time.Nanosecond)
				}
				return parsed.UTC(), nil
			}
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported time format")
}

func buildSecurityAuditCSV(events []SecurityAuditEvent) (string, error) {
	buffer := &bytes.Buffer{}
	writer := csv.NewWriter(buffer)
	header := []string{
		"id",
		"time",
		"action",
		"success",
		"actor_id",
		"actor_ip",
		"user_agent",
		"resource_type",
		"client_id",
		"previous_client_id",
		"provider_id",
		"organization_id",
		"slug",
		"previous_slug",
		"name",
		"stage",
		"reason",
		"error",
		"details_json",
	}
	if err := writer.Write(header); err != nil {
		return "", err
	}
	for _, event := range events {
		details := map[string]string{}
		if strings.TrimSpace(event.DetailsJSON) != "" {
			if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
				return "", err
			}
		}
		record := []string{
			event.EventID,
			event.Time.UTC().Format(time.RFC3339),
			event.Action,
			strconv.FormatBool(event.Success),
			event.ActorID,
			event.ActorIP,
			event.UserAgent,
			details["resource_type"],
			details["client_id"],
			details["previous_client_id"],
			details["provider_id"],
			details["organization_id"],
			details["slug"],
			details["previous_slug"],
			details["name"],
			details["stage"],
			details["reason"],
			event.Error,
			event.DetailsJSON,
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}
	return buffer.String(), nil
}
