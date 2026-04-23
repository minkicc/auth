/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"minki.cc/mkauth/server/auth"
	"minki.cc/mkauth/server/config"
)

const defaultHTTPActionTimeout = 3 * time.Second

type HTTPActionHook struct {
	id       string
	name     string
	events   map[HookEvent]struct{}
	url      string
	secret   string
	failOpen bool
	client   *http.Client
}

type HTTPActionRequest struct {
	PluginID       string            `json:"plugin_id"`
	Event          HookEvent         `json:"event"`
	Provider       string            `json:"provider,omitempty"`
	ClientID       string            `json:"client_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	IP             string            `json:"ip,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	User           *HTTPActionUser   `json:"user,omitempty"`
	Claims         map[string]any    `json:"claims,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type HTTPActionUser struct {
	UserID   string `json:"user_id"`
	Username string `json:"username,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	Avatar   string `json:"avatar,omitempty"`
	Status   string `json:"status,omitempty"`
}

type HTTPActionResponse struct {
	Allow    *bool             `json:"allow,omitempty"`
	Claims   map[string]any    `json:"claims,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Error    string            `json:"error,omitempty"`
}

func NewHTTPActionHook(cfg config.HTTPActionConfig) (*HTTPActionHook, error) {
	return NewHTTPActionHookWithClient(cfg, nil)
}

func NewHTTPActionHookWithClient(cfg config.HTTPActionConfig, client *http.Client) (*HTTPActionHook, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	id := strings.TrimSpace(cfg.ID)
	if id == "" {
		return nil, fmt.Errorf("http action id is required")
	}
	actionURL := strings.TrimSpace(cfg.URL)
	parsed, err := url.ParseRequestURI(actionURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("http action %s has invalid url", id)
	}
	timeout := HTTPActionTimeout(cfg.TimeoutMS)
	events := map[HookEvent]struct{}{}
	for _, event := range cfg.Events {
		event = strings.TrimSpace(event)
		if event == "" {
			continue
		}
		if !IsSupportedHookEvent(event) {
			return nil, fmt.Errorf("http action %s has unsupported event %q", id, event)
		}
		events[HookEvent(event)] = struct{}{}
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("http action %s must define at least one event", id)
	}
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = id
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &HTTPActionHook{
		id:       id,
		name:     name,
		events:   events,
		url:      actionURL,
		secret:   cfg.Secret,
		failOpen: cfg.FailOpen,
		client:   client,
	}, nil
}

func HTTPActionTimeout(timeoutMS int) time.Duration {
	if timeoutMS > 0 {
		return time.Duration(timeoutMS) * time.Millisecond
	}
	return defaultHTTPActionTimeout
}

func NewConfiguredHookRegistry(cfg config.PluginsConfig) (*HookRegistry, error) {
	registry, err := NewHookRegistry()
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return registry, nil
	}
	for _, action := range cfg.HTTPActions {
		hook, err := NewHTTPActionHook(action)
		if err != nil {
			return nil, err
		}
		if hook == nil {
			continue
		}
		if err := registry.Register(hook); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func (h *HTTPActionHook) Name() string {
	if h == nil {
		return ""
	}
	return h.id
}

func (h *HTTPActionHook) Handle(ctx context.Context, event HookEvent, data *HookContext) error {
	if h == nil {
		return nil
	}
	if _, ok := h.events[event]; !ok {
		return nil
	}
	if data == nil {
		data = &HookContext{}
	}

	payload := HTTPActionRequest{
		PluginID:       h.id,
		Event:          event,
		Provider:       data.Provider,
		ClientID:       data.ClientID,
		OrganizationID: data.OrganizationID,
		IP:             data.IP,
		UserAgent:      data.UserAgent,
		User:           httpActionUser(data.User),
		Claims:         data.Claims,
		Metadata:       data.Metadata,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MKAuth-Plugin-ID", h.id)
	req.Header.Set("X-MKAuth-Hook-Event", string(event))
	if h.secret != "" {
		req.Header.Set("Authorization", "Bearer "+h.secret)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		if h.failOpen {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if h.failOpen {
			return nil
		}
		return fmt.Errorf("http action returned status %d", resp.StatusCode)
	}

	var actionResp HTTPActionResponse
	if err := json.NewDecoder(resp.Body).Decode(&actionResp); err != nil {
		if h.failOpen {
			return nil
		}
		return err
	}
	if actionResp.Allow != nil && !*actionResp.Allow {
		if actionResp.Error != "" {
			return fmt.Errorf("http action denied request: %s", actionResp.Error)
		}
		return fmt.Errorf("http action denied request")
	}
	if len(actionResp.Claims) > 0 {
		if data.Claims == nil {
			data.Claims = map[string]any{}
		}
		for key, value := range actionResp.Claims {
			key = strings.TrimSpace(key)
			if key != "" {
				data.Claims[key] = value
			}
		}
	}
	if len(actionResp.Metadata) > 0 {
		if data.Metadata == nil {
			data.Metadata = map[string]string{}
		}
		for key, value := range actionResp.Metadata {
			key = strings.TrimSpace(key)
			if key != "" {
				data.Metadata[key] = value
			}
		}
	}
	return nil
}

func httpActionUser(user *auth.User) *HTTPActionUser {
	if user == nil {
		return nil
	}
	return &HTTPActionUser{
		UserID:   user.UserID,
		Username: user.Username,
		Nickname: user.Nickname,
		Avatar:   user.Avatar,
		Status:   string(user.Status),
	}
}
