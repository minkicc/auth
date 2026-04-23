package iam

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestHookRegistryRunsHooksInOrder(t *testing.T) {
	calls := []string{}
	registry, err := NewHookRegistry(
		HookFunc{HookName: "first", Fn: func(ctx context.Context, event HookEvent, data *HookContext) error {
			calls = append(calls, "first:"+string(event))
			data.Claims["first"] = true
			return nil
		}},
		HookFunc{HookName: "second", Fn: func(ctx context.Context, event HookEvent, data *HookContext) error {
			calls = append(calls, "second:"+string(event))
			if data.Claims["first"] != true {
				t.Fatalf("expected first hook to run before second hook")
			}
			return nil
		}},
	)
	if err != nil {
		t.Fatalf("failed to create hook registry: %v", err)
	}

	data := &HookContext{Claims: map[string]any{}}
	if err := registry.Run(context.Background(), HookBeforeTokenIssue, data); err != nil {
		t.Fatalf("failed to run hooks: %v", err)
	}

	expected := []string{"first:before_token_issue", "second:before_token_issue"}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("expected calls %v, got %v", expected, calls)
	}
}

func TestHookRegistryStopsOnError(t *testing.T) {
	boom := errors.New("boom")
	calls := []string{}
	registry, err := NewHookRegistry(
		HookFunc{HookName: "broken", Fn: func(ctx context.Context, event HookEvent, data *HookContext) error {
			calls = append(calls, "broken")
			return boom
		}},
		HookFunc{HookName: "skipped", Fn: func(ctx context.Context, event HookEvent, data *HookContext) error {
			calls = append(calls, "skipped")
			return nil
		}},
	)
	if err != nil {
		t.Fatalf("failed to create hook registry: %v", err)
	}

	err = registry.Run(context.Background(), HookPostAuthenticate, &HookContext{})
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped hook error, got %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"broken"}) {
		t.Fatalf("expected registry to stop after failed hook, got calls %v", calls)
	}
}

func TestHookRegistryRejectsUnnamedHooks(t *testing.T) {
	_, err := NewHookRegistry(HookFunc{})
	if err == nil {
		t.Fatalf("expected unnamed hook to be rejected")
	}
}
