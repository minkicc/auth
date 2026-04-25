package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/plugins"
)

const (
	securityAuditExportJobStatusPending       = "pending"
	securityAuditExportJobStatusRunning       = "running"
	securityAuditExportJobStatusCompleted     = "completed"
	securityAuditExportJobStatusFailed        = "failed"
	securityAuditExportJobRetentionDays       = 7
	securityAuditExportJobAutoCleanupInterval = time.Hour
)

type SecurityAuditExportJob struct {
	JobID       string     `json:"job_id" gorm:"primaryKey;size:40"`
	Status      string     `json:"status" gorm:"index;size:20;not null"`
	QueryJSON   string     `json:"query_json,omitempty" gorm:"type:text"`
	FileName    string     `json:"filename" gorm:"size:255;not null"`
	ContentType string     `json:"content_type" gorm:"size:120;not null"`
	Content     string     `json:"-" gorm:"type:longtext"`
	RowCount    int        `json:"row_count" gorm:"not null"`
	TotalCount  int64      `json:"total_count" gorm:"not null"`
	Truncated   bool       `json:"truncated" gorm:"not null"`
	Error       string     `json:"error,omitempty" gorm:"type:text"`
	ActorID     string     `json:"actor_id,omitempty" gorm:"size:120"`
	ActorIP     string     `json:"actor_ip,omitempty" gorm:"size:80"`
	UserAgent   string     `json:"user_agent,omitempty" gorm:"size:255"`
	CreatedAt   time.Time  `json:"created_at" gorm:"index;not null"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"index;not null"`
	CompletedAt *time.Time `json:"completed_at,omitempty" gorm:"index"`
}

func (SecurityAuditExportJob) TableName() string {
	return "admin_security_audit_export_jobs"
}

type securityAuditExportJobRequest struct {
	Action         string `json:"action,omitempty"`
	ResourceType   string `json:"resource_type,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	ProviderID     string `json:"provider_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ActorID        string `json:"actor_id,omitempty"`
	Query          string `json:"query,omitempty"`
	TimeFrom       string `json:"time_from,omitempty"`
	TimeTo         string `json:"time_to,omitempty"`
	Success        *bool  `json:"success,omitempty"`
}

type securityAuditExportJobView struct {
	JobID         string                         `json:"job_id"`
	Status        string                         `json:"status"`
	FileName      string                         `json:"filename"`
	ContentType   string                         `json:"content_type"`
	RowCount      int                            `json:"row_count"`
	TotalCount    int64                          `json:"total_count"`
	Truncated     bool                           `json:"truncated"`
	Error         string                         `json:"error,omitempty"`
	CreatedAt     string                         `json:"created_at"`
	UpdatedAt     string                         `json:"updated_at"`
	CompletedAt   string                         `json:"completed_at,omitempty"`
	DownloadReady bool                           `json:"download_ready"`
	Query         *securityAuditExportJobRequest `json:"query,omitempty"`
	Actor         plugins.AuditActor             `json:"actor,omitempty"`
}

type securityAuditExportJobListOptions struct {
	Page           int
	Size           int
	Status         string
	OrganizationID string
}

type securityAuditExportJobListResult struct {
	Jobs  []securityAuditExportJobView `json:"jobs"`
	Total int64                        `json:"total"`
	Page  int                          `json:"page"`
	Size  int                          `json:"size"`
}

type securityAuditExportJobCleanupRequest struct {
	OrganizationID string `json:"organization_id,omitempty"`
	OlderThanDays  int    `json:"older_than_days,omitempty"`
	Status         string `json:"status,omitempty"`
}

type securityAuditExportJobCleanupResult struct {
	Deleted       int    `json:"deleted"`
	OlderThanDays int    `json:"older_than_days"`
	Status        string `json:"status"`
}

func (s *AdminServer) ensureSecurityAuditExportJobTable() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("admin server requires database")
	}
	return s.db.AutoMigrate(&SecurityAuditExportJob{})
}

func (s *AdminServer) createSecurityAuditExportJob(request securityAuditExportJobRequest, actor plugins.AuditActor) (SecurityAuditExportJob, error) {
	if s == nil || s.db == nil {
		return SecurityAuditExportJob{}, fmt.Errorf("admin server requires database")
	}
	if err := s.ensureSecurityAuditExportJobTable(); err != nil {
		return SecurityAuditExportJob{}, err
	}
	jobID, err := generateSecurityAuditExportJobID()
	if err != nil {
		return SecurityAuditExportJob{}, err
	}
	queryJSON, err := json.Marshal(request)
	if err != nil {
		return SecurityAuditExportJob{}, err
	}
	now := time.Now().UTC()
	record := SecurityAuditExportJob{
		JobID:       jobID,
		Status:      securityAuditExportJobStatusPending,
		QueryJSON:   string(queryJSON),
		FileName:    fmt.Sprintf("security-audit-%s.csv", now.Format("20060102-150405")),
		ContentType: "text/csv; charset=utf-8",
		ActorID:     actor.ID,
		ActorIP:     actor.IP,
		UserAgent:   actor.UserAgent,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.Create(&record).Error; err != nil {
		return SecurityAuditExportJob{}, err
	}
	return record, nil
}

func (s *AdminServer) getSecurityAuditExportJob(jobID string) (SecurityAuditExportJob, error) {
	if s == nil || s.db == nil {
		return SecurityAuditExportJob{}, fmt.Errorf("admin server requires database")
	}
	if err := s.ensureSecurityAuditExportJobTable(); err != nil {
		return SecurityAuditExportJob{}, err
	}
	var record SecurityAuditExportJob
	if err := s.db.Where("job_id = ?", strings.TrimSpace(jobID)).First(&record).Error; err != nil {
		return SecurityAuditExportJob{}, err
	}
	return record, nil
}

func (s *AdminServer) listSecurityAuditExportJobs(options securityAuditExportJobListOptions) (securityAuditExportJobListResult, error) {
	if s == nil || s.db == nil {
		return securityAuditExportJobListResult{}, fmt.Errorf("admin server requires database")
	}
	if err := s.ensureSecurityAuditExportJobTable(); err != nil {
		return securityAuditExportJobListResult{}, err
	}
	if options.Page <= 0 {
		options.Page = 1
	}
	if options.Size <= 0 {
		options.Size = 10
	}
	if options.Size > 100 {
		options.Size = 100
	}

	query := s.db.Model(&SecurityAuditExportJob{})
	if status := strings.TrimSpace(strings.ToLower(options.Status)); status != "" {
		query = query.Where("LOWER(status) = ?", status)
	}
	if organizationID := strings.TrimSpace(options.OrganizationID); organizationID != "" {
		query = query.Where("query_json LIKE ? ESCAPE '\\'", securityAuditJSONFieldPattern("organization_id", organizationID))
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return securityAuditExportJobListResult{}, err
	}

	var records []SecurityAuditExportJob
	offset := (options.Page - 1) * options.Size
	if err := query.Order("created_at DESC").Offset(offset).Limit(options.Size).Find(&records).Error; err != nil {
		return securityAuditExportJobListResult{}, err
	}
	views := make([]securityAuditExportJobView, 0, len(records))
	for _, record := range records {
		view, err := securityAuditExportJobViewFromRecord(record)
		if err != nil {
			return securityAuditExportJobListResult{}, err
		}
		views = append(views, view)
	}
	return securityAuditExportJobListResult{
		Jobs:  views,
		Total: total,
		Page:  options.Page,
		Size:  options.Size,
	}, nil
}

func (s *AdminServer) deleteSecurityAuditExportJob(jobID string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("admin server requires database")
	}
	if err := s.ensureSecurityAuditExportJobTable(); err != nil {
		return err
	}
	trimmedJobID := strings.TrimSpace(jobID)
	record, err := s.getSecurityAuditExportJob(trimmedJobID)
	if err != nil {
		return err
	}
	if record.Status == securityAuditExportJobStatusPending || record.Status == securityAuditExportJobStatusRunning {
		return fmt.Errorf("security audit export job is still running")
	}
	return s.db.Where("job_id = ?", trimmedJobID).Delete(&SecurityAuditExportJob{}).Error
}

func (s *AdminServer) cleanupSecurityAuditExportJobs(request securityAuditExportJobCleanupRequest) (securityAuditExportJobCleanupResult, error) {
	if s == nil || s.db == nil {
		return securityAuditExportJobCleanupResult{}, fmt.Errorf("admin server requires database")
	}
	if err := s.ensureSecurityAuditExportJobTable(); err != nil {
		return securityAuditExportJobCleanupResult{}, err
	}
	retentionDays := request.OlderThanDays
	if retentionDays <= 0 {
		retentionDays = s.exportJobRetentionDays
		if retentionDays <= 0 {
			retentionDays = securityAuditExportJobRetentionDays
		}
	}
	statuses, err := securityAuditExportJobStatusesForCleanup(request.Status)
	if err != nil {
		return securityAuditExportJobCleanupResult{}, err
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	query := s.db.Model(&SecurityAuditExportJob{}).Where("status IN ?", statuses).Where("completed_at IS NOT NULL").Where("completed_at <= ?", cutoff)
	if organizationID := strings.TrimSpace(request.OrganizationID); organizationID != "" {
		query = query.Where("query_json LIKE ? ESCAPE '\\'", securityAuditJSONFieldPattern("organization_id", organizationID))
	}
	result := query.Delete(&SecurityAuditExportJob{})
	if result.Error != nil {
		return securityAuditExportJobCleanupResult{}, result.Error
	}
	return securityAuditExportJobCleanupResult{
		Deleted:       int(result.RowsAffected),
		OlderThanDays: retentionDays,
		Status:        strings.Join(statuses, ","),
	}, nil
}

func (s *AdminServer) startSecurityAuditExportJobAutoCleanupLoop() {
	if s == nil || s.db == nil || !s.exportJobAutoCleanup || s.exportJobCleanupCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.exportJobCleanupCancel = cancel
	s.exportJobCleanupDone = done
	go func() {
		defer close(done)
		s.runSecurityAuditExportJobAutoCleanup()
		ticker := time.NewTicker(securityAuditExportJobAutoCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runSecurityAuditExportJobAutoCleanup()
			}
		}
	}()
}

func (s *AdminServer) stopSecurityAuditExportJobAutoCleanupLoop() {
	if s == nil || s.exportJobCleanupCancel == nil {
		return
	}
	s.exportJobCleanupCancel()
	if s.exportJobCleanupDone != nil {
		<-s.exportJobCleanupDone
	}
	s.exportJobCleanupCancel = nil
	s.exportJobCleanupDone = nil
}

func (s *AdminServer) runSecurityAuditExportJobAutoCleanup() {
	if s == nil || s.db == nil || !s.exportJobAutoCleanup {
		return
	}
	result, err := s.cleanupSecurityAuditExportJobs(securityAuditExportJobCleanupRequest{
		OlderThanDays: s.exportJobRetentionDays,
	})
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("security audit export auto cleanup failed: %v", err)
		}
		return
	}
	if result.Deleted > 0 && s.logger != nil {
		s.logger.Printf("security audit export auto cleanup removed %d settled jobs older than %d days", result.Deleted, result.OlderThanDays)
	}
}

func (s *AdminServer) processSecurityAuditExportJob(jobID string, options securityAuditListOptions) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.failSecurityAuditExportJob(jobID, fmt.Errorf("panic: %v", recovered))
		}
	}()

	now := time.Now().UTC()
	if err := s.db.Model(&SecurityAuditExportJob{}).
		Where("job_id = ?", jobID).
		Updates(map[string]any{
			"status":       securityAuditExportJobStatusRunning,
			"error":        "",
			"updated_at":   now,
			"completed_at": nil,
		}).Error; err != nil {
		s.failSecurityAuditExportJob(jobID, err)
		return
	}

	events, total, truncated, err := s.listSecurityAuditEventsForExport(options, securityAuditExportMaxRows)
	if err != nil {
		s.failSecurityAuditExportJob(jobID, err)
		return
	}
	content, err := buildSecurityAuditCSV(events)
	if err != nil {
		s.failSecurityAuditExportJob(jobID, err)
		return
	}

	completedAt := time.Now().UTC()
	if err := s.db.Model(&SecurityAuditExportJob{}).
		Where("job_id = ?", jobID).
		Updates(map[string]any{
			"status":       securityAuditExportJobStatusCompleted,
			"content":      content,
			"row_count":    len(events),
			"total_count":  total,
			"truncated":    truncated,
			"error":        "",
			"updated_at":   completedAt,
			"completed_at": completedAt,
		}).Error; err != nil {
		s.failSecurityAuditExportJob(jobID, err)
		return
	}
	s.runSecurityAuditExportJobAutoCleanup()
}

func (s *AdminServer) failSecurityAuditExportJob(jobID string, err error) {
	if s == nil || s.db == nil {
		return
	}
	completedAt := time.Now().UTC()
	updateErr := s.db.Model(&SecurityAuditExportJob{}).
		Where("job_id = ?", strings.TrimSpace(jobID)).
		Updates(map[string]any{
			"status":       securityAuditExportJobStatusFailed,
			"error":        err.Error(),
			"updated_at":   completedAt,
			"completed_at": completedAt,
		}).Error
	if updateErr != nil && s.logger != nil {
		s.logger.Printf("failed to mark security audit export job %s as failed: %v", jobID, updateErr)
	}
	s.runSecurityAuditExportJobAutoCleanup()
}

func securityAuditExportJobRequestFromOptions(options securityAuditListOptions) securityAuditExportJobRequest {
	request := securityAuditExportJobRequest{
		Action:         strings.TrimSpace(options.Action),
		ResourceType:   strings.TrimSpace(options.ResourceType),
		ClientID:       strings.TrimSpace(options.ClientID),
		ProviderID:     strings.TrimSpace(options.ProviderID),
		OrganizationID: strings.TrimSpace(options.OrganizationID),
		ActorID:        strings.TrimSpace(options.ActorID),
		Query:          strings.TrimSpace(options.Query),
		Success:        options.Success,
	}
	if options.TimeFrom != nil {
		request.TimeFrom = options.TimeFrom.UTC().Format(time.RFC3339)
	}
	if options.TimeTo != nil {
		request.TimeTo = options.TimeTo.UTC().Format(time.RFC3339)
	}
	return request
}

func securityAuditListOptionsFromExportRequest(request securityAuditExportJobRequest) (securityAuditListOptions, error) {
	options := securityAuditListOptions{
		Action:         strings.TrimSpace(request.Action),
		ResourceType:   strings.TrimSpace(strings.ToLower(request.ResourceType)),
		ClientID:       strings.TrimSpace(request.ClientID),
		ProviderID:     strings.TrimSpace(request.ProviderID),
		OrganizationID: strings.TrimSpace(request.OrganizationID),
		ActorID:        strings.TrimSpace(request.ActorID),
		Query:          strings.TrimSpace(request.Query),
		Success:        request.Success,
	}
	if rawTimeFrom := strings.TrimSpace(request.TimeFrom); rawTimeFrom != "" {
		parsed, err := parseSecurityAuditTime(rawTimeFrom, false)
		if err != nil {
			return securityAuditListOptions{}, fmt.Errorf("time_from must be RFC3339 or YYYY-MM-DD")
		}
		options.TimeFrom = &parsed
	}
	if rawTimeTo := strings.TrimSpace(request.TimeTo); rawTimeTo != "" {
		parsed, err := parseSecurityAuditTime(rawTimeTo, true)
		if err != nil {
			return securityAuditListOptions{}, fmt.Errorf("time_to must be RFC3339 or YYYY-MM-DD")
		}
		options.TimeTo = &parsed
	}
	if options.TimeFrom != nil && options.TimeTo != nil && options.TimeFrom.After(*options.TimeTo) {
		return securityAuditListOptions{}, fmt.Errorf("time_from must be earlier than or equal to time_to")
	}
	return options, nil
}

func securityAuditExportJobViewFromRecord(record SecurityAuditExportJob) (securityAuditExportJobView, error) {
	view := securityAuditExportJobView{
		JobID:         record.JobID,
		Status:        record.Status,
		FileName:      record.FileName,
		ContentType:   record.ContentType,
		RowCount:      record.RowCount,
		TotalCount:    record.TotalCount,
		Truncated:     record.Truncated,
		Error:         record.Error,
		CreatedAt:     record.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:     record.UpdatedAt.UTC().Format(time.RFC3339),
		DownloadReady: record.Status == securityAuditExportJobStatusCompleted && strings.TrimSpace(record.Content) != "",
		Actor: plugins.AuditActor{
			ID:        record.ActorID,
			IP:        record.ActorIP,
			UserAgent: record.UserAgent,
		},
	}
	if record.CompletedAt != nil {
		view.CompletedAt = record.CompletedAt.UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(record.QueryJSON) != "" {
		var request securityAuditExportJobRequest
		if err := json.Unmarshal([]byte(record.QueryJSON), &request); err != nil {
			return securityAuditExportJobView{}, err
		}
		view.Query = &request
	}
	return view, nil
}

func generateSecurityAuditExportJobID() (string, error) {
	suffix, err := auth.GenerateReadableRandomString(16)
	if err != nil {
		return "", err
	}
	return "secaudexp_" + suffix, nil
}

func securityAuditExportJobStatusesForCleanup(raw string) ([]string, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", "settled":
		return []string{securityAuditExportJobStatusCompleted, securityAuditExportJobStatusFailed}, nil
	case securityAuditExportJobStatusCompleted:
		return []string{securityAuditExportJobStatusCompleted}, nil
	case securityAuditExportJobStatusFailed:
		return []string{securityAuditExportJobStatusFailed}, nil
	default:
		return nil, fmt.Errorf("status must be completed, failed, or settled")
	}
}
