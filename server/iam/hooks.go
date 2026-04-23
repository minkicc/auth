/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package iam

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"minki.cc/mkauth/server/auth"
)

type HookEvent string

const (
	HookPreRegister      HookEvent = "pre_register"
	HookPostRegister     HookEvent = "post_register"
	HookPreAuthenticate  HookEvent = "pre_authenticate"
	HookPostAuthenticate HookEvent = "post_authenticate"
	HookBeforeTokenIssue HookEvent = "before_token_issue"
	HookBeforeUserInfo   HookEvent = "before_userinfo"
	HookPostLogout       HookEvent = "post_logout"
)

func IsSupportedHookEvent(event string) bool {
	switch HookEvent(strings.TrimSpace(event)) {
	case HookPreRegister, HookPostRegister, HookPreAuthenticate, HookPostAuthenticate, HookBeforeTokenIssue, HookBeforeUserInfo, HookPostLogout:
		return true
	default:
		return false
	}
}

// HookContext is the stable envelope passed to flow/action plugins.
type HookContext struct {
	User           *auth.User
	Provider       string
	ClientID       string
	OrganizationID string
	IP             string
	UserAgent      string
	Claims         map[string]any
	Metadata       map[string]string
}

type Hook interface {
	Name() string
	Handle(ctx context.Context, event HookEvent, data *HookContext) error
}

type HookFunc struct {
	HookName string
	Fn       func(ctx context.Context, event HookEvent, data *HookContext) error
}

func (h HookFunc) Name() string {
	return h.HookName
}

func (h HookFunc) Handle(ctx context.Context, event HookEvent, data *HookContext) error {
	if h.Fn == nil {
		return nil
	}
	return h.Fn(ctx, event, data)
}

// HookRegistry runs registered hooks in order. It is intentionally small so
// HTTP/JS/WASM actions can share the same boundary later.
type HookRegistry struct {
	mu    sync.RWMutex
	hooks []Hook
}

func NewHookRegistry(hooks ...Hook) (*HookRegistry, error) {
	r := &HookRegistry{}
	for _, hook := range hooks {
		if err := r.Register(hook); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *HookRegistry) Register(hook Hook) error {
	if hook == nil {
		return fmt.Errorf("iam hook is nil")
	}
	if strings.TrimSpace(hook.Name()) == "" {
		return fmt.Errorf("iam hook name is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = append(r.hooks, hook)
	return nil
}

func (r *HookRegistry) Run(ctx context.Context, event HookEvent, data *HookContext) error {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	hooks := append([]Hook(nil), r.hooks...)
	r.mu.RUnlock()
	for _, hook := range hooks {
		if err := hook.Handle(ctx, event, data); err != nil {
			return fmt.Errorf("iam hook %s failed: %w", hook.Name(), err)
		}
	}
	return nil
}

func (r *HookRegistry) Replace(hooks []Hook) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks = append([]Hook(nil), hooks...)
}
