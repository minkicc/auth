package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"minki.cc/mkauth/server/iam"
)

const defaultHTTPAuditSinkTimeout = 3 * time.Second

const auditSinkLifecycleResourceType = "auth_lifecycle"

type SecurityAuditSinkEvent struct {
	ID      string            `json:"id"`
	Time    string            `json:"time"`
	Action  string            `json:"action"`
	Actor   AuditActor        `json:"actor,omitempty"`
	Success bool              `json:"success"`
	Error   string            `json:"error,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

type LifecycleSinkEvent struct {
	Time           string            `json:"time"`
	Event          string            `json:"event"`
	UserID         string            `json:"user_id,omitempty"`
	Provider       string            `json:"provider,omitempty"`
	ClientID       string            `json:"client_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	IP             string            `json:"ip,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type AuditSink interface {
	Name() string
	DispatchSecurityAudit(ctx context.Context, event SecurityAuditSinkEvent) error
	DispatchLifecycle(ctx context.Context, event LifecycleSinkEvent) error
}

type AuditSinkRegistry struct {
	mu    sync.RWMutex
	sinks []AuditSink
}

func NewAuditSinkRegistry(sinks ...AuditSink) (*AuditSinkRegistry, error) {
	registry := &AuditSinkRegistry{}
	for _, sink := range sinks {
		if err := registry.Register(sink); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func (r *AuditSinkRegistry) Register(sink AuditSink) error {
	if sink == nil {
		return fmt.Errorf("audit sink is nil")
	}
	if strings.TrimSpace(sink.Name()) == "" {
		return fmt.Errorf("audit sink name is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sinks = append(r.sinks, sink)
	return nil
}

func (r *AuditSinkRegistry) Replace(sinks []AuditSink) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sinks = append([]AuditSink(nil), sinks...)
}

func (r *AuditSinkRegistry) DispatchSecurityAudit(ctx context.Context, event SecurityAuditSinkEvent) error {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	sinks := append([]AuditSink(nil), r.sinks...)
	r.mu.RUnlock()
	var failures []string
	for _, sink := range sinks {
		if err := sink.DispatchSecurityAudit(ctx, event); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", sink.Name(), err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("audit sink dispatch failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (r *AuditSinkRegistry) DispatchLifecycle(ctx context.Context, event LifecycleSinkEvent) error {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	sinks := append([]AuditSink(nil), r.sinks...)
	r.mu.RUnlock()
	var failures []string
	for _, sink := range sinks {
		if err := sink.DispatchLifecycle(ctx, event); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", sink.Name(), err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("audit sink dispatch failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

type HTTPAuditSinkConfig struct {
	ID            string
	Name          string
	Enabled       bool
	URL           string
	Secret        string
	TimeoutMS     int
	FailOpen      bool
	Actions       []string
	ResourceTypes []string
	SuccessOnly   bool
	FailureOnly   bool
}

type HTTPAuditSink struct {
	id            string
	name          string
	url           string
	secret        string
	failOpen      bool
	actions       map[string]struct{}
	resourceTypes map[string]struct{}
	successOnly   bool
	failureOnly   bool
	client        *http.Client
}

func NewHTTPAuditSinkWithClient(cfg HTTPAuditSinkConfig, client *http.Client) (*HTTPAuditSink, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	id := strings.TrimSpace(cfg.ID)
	if id == "" {
		return nil, fmt.Errorf("audit sink id is required")
	}
	sinkURL := strings.TrimSpace(cfg.URL)
	parsed, err := url.ParseRequestURI(sinkURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("audit sink %s has invalid url", id)
	}
	if cfg.SuccessOnly && cfg.FailureOnly {
		return nil, fmt.Errorf("audit sink %s cannot set both success_only and failure_only", id)
	}
	if client == nil {
		client = &http.Client{Timeout: HTTPAuditSinkTimeout(cfg.TimeoutMS)}
	}
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = id
	}
	return &HTTPAuditSink{
		id:            id,
		name:          name,
		url:           sinkURL,
		secret:        cfg.Secret,
		failOpen:      cfg.FailOpen,
		actions:       auditSinkStringSet(cfg.Actions),
		resourceTypes: auditSinkStringSet(cfg.ResourceTypes),
		successOnly:   cfg.SuccessOnly,
		failureOnly:   cfg.FailureOnly,
		client:        client,
	}, nil
}

func HTTPAuditSinkTimeout(timeoutMS int) time.Duration {
	if timeoutMS > 0 {
		return time.Duration(timeoutMS) * time.Millisecond
	}
	return defaultHTTPAuditSinkTimeout
}

func (s *HTTPAuditSink) Name() string {
	if s == nil {
		return ""
	}
	return s.id
}

func (s *HTTPAuditSink) DispatchSecurityAudit(ctx context.Context, event SecurityAuditSinkEvent) error {
	if s == nil || !s.matches(event) {
		return nil
	}
	payload := struct {
		PluginID string                 `json:"plugin_id"`
		Event    string                 `json:"event"`
		Audit    SecurityAuditSinkEvent `json:"audit"`
	}{
		PluginID: s.id,
		Event:    "security_audit",
		Audit:    event,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MKAuth-Plugin-ID", s.id)
	req.Header.Set("X-MKAuth-Audit-Event", "security_audit")
	if s.secret != "" {
		req.Header.Set("Authorization", "Bearer "+s.secret)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if s.failOpen {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if s.failOpen {
			return nil
		}
		return fmt.Errorf("audit sink returned status %d", resp.StatusCode)
	}
	return nil
}

func (s *HTTPAuditSink) DispatchLifecycle(ctx context.Context, event LifecycleSinkEvent) error {
	if s == nil || !s.matchesLifecycle(event) {
		return nil
	}
	payload := struct {
		PluginID  string             `json:"plugin_id"`
		Event     string             `json:"event"`
		Lifecycle LifecycleSinkEvent `json:"lifecycle"`
	}{
		PluginID:  s.id,
		Event:     "lifecycle",
		Lifecycle: event,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MKAuth-Plugin-ID", s.id)
	req.Header.Set("X-MKAuth-Audit-Event", "lifecycle")
	if s.secret != "" {
		req.Header.Set("Authorization", "Bearer "+s.secret)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if s.failOpen {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if s.failOpen {
			return nil
		}
		return fmt.Errorf("audit sink returned status %d", resp.StatusCode)
	}
	return nil
}

func (s *HTTPAuditSink) matches(event SecurityAuditSinkEvent) bool {
	if s.successOnly && !event.Success {
		return false
	}
	if s.failureOnly && event.Success {
		return false
	}
	if len(s.actions) > 0 {
		if _, ok := s.actions[strings.ToLower(strings.TrimSpace(event.Action))]; !ok {
			return false
		}
	}
	if len(s.resourceTypes) > 0 {
		resourceType := strings.ToLower(strings.TrimSpace(event.Details["resource_type"]))
		if _, ok := s.resourceTypes[resourceType]; !ok {
			return false
		}
	}
	return true
}

func (s *HTTPAuditSink) matchesLifecycle(event LifecycleSinkEvent) bool {
	if len(s.actions) == 0 && len(s.resourceTypes) == 0 {
		return false
	}
	actionMatched := len(s.actions) == 0
	if len(s.actions) > 0 {
		_, actionMatched = s.actions[strings.ToLower(strings.TrimSpace(event.Event))]
	}
	resourceMatched := len(s.resourceTypes) == 0
	if len(s.resourceTypes) > 0 {
		_, resourceMatched = s.resourceTypes[auditSinkLifecycleResourceType]
	}
	return actionMatched && resourceMatched
}

func auditSinkStringSet(items []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, item := range normalizeStringList(items, true) {
		set[item] = struct{}{}
	}
	return set
}

type lifecycleAuditHook struct {
	sinks *AuditSinkRegistry
}

func newLifecycleAuditHook(sinks *AuditSinkRegistry) iam.Hook {
	return lifecycleAuditHook{sinks: sinks}
}

func (h lifecycleAuditHook) Name() string {
	return "audit_sink_lifecycle"
}

func (h lifecycleAuditHook) Handle(ctx context.Context, event iam.HookEvent, data *iam.HookContext) error {
	if h.sinks == nil || data == nil {
		return nil
	}
	sinkEvent := LifecycleSinkEvent{
		Time:           time.Now().UTC().Format(time.RFC3339),
		Event:          string(event),
		Provider:       data.Provider,
		ClientID:       data.ClientID,
		OrganizationID: data.OrganizationID,
		IP:             data.IP,
		UserAgent:      data.UserAgent,
		Metadata:       cloneLifecycleMetadata(data.Metadata),
	}
	if data.User != nil {
		sinkEvent.UserID = data.User.UserID
	}
	if err := h.sinks.DispatchLifecycle(ctx, sinkEvent); err != nil {
		log.Printf("Failed to dispatch lifecycle audit sink event %s: %v", event, err)
	}
	return nil
}

func cloneLifecycleMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(metadata))
	for key, value := range metadata {
		cloned[key] = value
	}
	return cloned
}
