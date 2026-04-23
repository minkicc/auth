package plugins

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const AuditFileName = "mkauth-plugin.audit.jsonl"

type AuditActor struct {
	ID        string `json:"id,omitempty"`
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type AuditEvent struct {
	ID         string            `json:"id"`
	Time       string            `json:"time"`
	Action     string            `json:"action"`
	PluginID   string            `json:"plugin_id,omitempty"`
	PluginName string            `json:"plugin_name,omitempty"`
	Version    string            `json:"version,omitempty"`
	Source     string            `json:"source,omitempty"`
	Actor      AuditActor        `json:"actor,omitempty"`
	Success    bool              `json:"success"`
	Error      string            `json:"error,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
}

type auditActorKey struct{}

func ContextWithAuditActor(ctx context.Context, actor AuditActor) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, auditActorKey{}, normalizeAuditActor(actor))
}

func AuditActorFromContext(ctx context.Context) AuditActor {
	if ctx == nil {
		return AuditActor{}
	}
	actor, _ := ctx.Value(auditActorKey{}).(AuditActor)
	return normalizeAuditActor(actor)
}

func (r *Runtime) ListAudit(limit int) ([]AuditEvent, error) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listAuditLocked(limit)
}

func (r *Runtime) listAuditLocked(limit int) ([]AuditEvent, error) {
	path, err := r.auditFilePathLocked(false)
	if err != nil {
		return nil, err
	}
	content, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEvent{}, nil
		}
		return nil, fmt.Errorf("open plugin audit log: %w", err)
	}
	defer content.Close()

	events := make([]AuditEvent, 0)
	scanner := bufio.NewScanner(content)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("parse plugin audit log: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read plugin audit log: %w", err)
	}

	reverseAuditEvents(events)
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func (r *Runtime) appendAuditLocked(event AuditEvent) {
	if r == nil {
		return
	}
	path, err := r.auditFilePathLocked(true)
	if err != nil {
		return
	}
	event = normalizeAuditEvent(event)
	content, err := json.Marshal(event)
	if err != nil {
		return
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(content, '\n'))
}

func (r *Runtime) appendAudit(event AuditEvent) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.appendAuditLocked(event)
}

func (r *Runtime) auditFilePathLocked(create bool) (string, error) {
	directory := ""
	if create {
		var err error
		directory, err = r.primaryDirectory()
		if err != nil {
			return "", err
		}
	} else {
		for _, item := range r.cfg.Directories {
			item = strings.TrimSpace(item)
			if item != "" {
				directory = item
				break
			}
		}
		if directory == "" {
			directory = "plugins"
		}
	}
	return filepath.Join(directory, AuditFileName), nil
}

func normalizeAuditEvent(event AuditEvent) AuditEvent {
	event.ID = strings.TrimSpace(event.ID)
	if event.ID == "" {
		event.ID = newAuditID()
	}
	event.Time = strings.TrimSpace(event.Time)
	if event.Time == "" {
		event.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	event.Action = strings.TrimSpace(event.Action)
	event.PluginID = strings.TrimSpace(event.PluginID)
	event.PluginName = strings.TrimSpace(event.PluginName)
	event.Version = strings.TrimSpace(event.Version)
	event.Source = strings.TrimSpace(event.Source)
	event.Actor = normalizeAuditActor(event.Actor)
	event.Error = strings.TrimSpace(event.Error)
	if len(event.Details) == 0 {
		event.Details = nil
	}
	return event
}

func normalizeAuditActor(actor AuditActor) AuditActor {
	return AuditActor{
		ID:        strings.TrimSpace(actor.ID),
		IP:        strings.TrimSpace(actor.IP),
		UserAgent: strings.TrimSpace(actor.UserAgent),
	}
}

func auditError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func auditSummaryDetails(summary Summary) map[string]string {
	details := map[string]string{}
	if summary.PackageSHA256 != "" {
		details["package_sha256"] = summary.PackageSHA256
	}
	if summary.Source != "" {
		details["plugin_source"] = string(summary.Source)
	}
	if summary.Entry != "" {
		details["entry"] = summary.Entry
	}
	if len(details) == 0 {
		return nil
	}
	return details
}

func auditPreviousSummaryDetails(summary Summary) map[string]string {
	details := map[string]string{}
	if summary.PackageSHA256 != "" {
		details["previous_package_sha256"] = summary.PackageSHA256
	}
	if summary.Version != "" {
		details["previous_version"] = summary.Version
	}
	if summary.Source != "" {
		details["previous_plugin_source"] = string(summary.Source)
	}
	if len(details) == 0 {
		return nil
	}
	return details
}

func mergeAuditDetails(items ...map[string]string) map[string]string {
	merged := map[string]string{}
	for _, item := range items {
		for key, value := range item {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key != "" && value != "" {
				merged[key] = value
			}
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func newAuditID() string {
	now := time.Now().UTC().Format("20060102T150405.000000000Z")
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return now
	}
	return now + "-" + hex.EncodeToString(random)
}

func reverseAuditEvents(events []AuditEvent) {
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
}
