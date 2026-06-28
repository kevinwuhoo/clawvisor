package gatewayhooks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/clawvisor/clawvisor/pkg/adapters"
	"github.com/clawvisor/clawvisor/pkg/config"
)

type fakeCaller struct {
	responses []HookResponse
	errs      []error
	seen      []HookRequest
}

func (f *fakeCaller) Call(ctx context.Context, cfg config.GatewayHookHandlerConfig, req HookRequest) (HookResponse, HandlerSummary, error) {
	f.seen = append(f.seen, req)
	idx := len(f.seen) - 1

	var resp HookResponse
	if idx < len(f.responses) {
		resp = f.responses[idx]
	}

	var err error
	if idx < len(f.errs) {
		err = f.errs[idx]
	}

	summary := HandlerSummary{
		Name:                cfg.Name,
		FailureMode:         cfg.FailureMode,
		Decision:            resp.Decision,
		UpdatedToolResponse: resp.UpdatedToolResponse != nil,
		Metadata:            resp.AuditMetadata,
	}
	if err != nil {
		summary.Error = err.Error()
	}
	return resp, summary, err
}

func TestRunnerAppliesUpdatedToolResponse(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{{
			HookEventName: EventGatewayPostToolCall,
			Decision:      DecisionContinue,
			UpdatedToolResponse: &adapters.Result{
				Summary: "redacted",
			},
			AuditMetadata: map[string]any{"redaction": "applied"},
		}},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:                "privacy-filter",
		FailureMode:         "fail_closed",
		AllowResponseUpdate: true,
	}), caller)

	result, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err != nil {
		t.Fatalf("RunPostToolCall returned error: %v", err)
	}
	if result.ToolResponse == nil {
		t.Fatal("ToolResponse is nil")
	}
	if got := result.ToolResponse.Summary; got != "redacted" {
		t.Fatalf("ToolResponse.Summary = %q, want redacted", got)
	}
	if got := len(caller.seen); got != 1 {
		t.Fatalf("hook calls = %d, want 1", got)
	}
	assertFiltersAppliedValidJSON(t, result.FiltersApplied)
}

func TestRunnerRejectsUnauthorizedMutation(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{{
			HookEventName: EventGatewayPostToolCall,
			Decision:      DecisionContinue,
			UpdatedToolResponse: &adapters.Result{
				Summary: "redacted",
			},
		}},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:        "privacy-filter",
		FailureMode: "fail_closed",
	}), caller)

	_, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err == nil {
		t.Fatal("RunPostToolCall returned nil error, want HookError")
	}
	var hookErr *HookError
	if !errors.As(err, &hookErr) {
		t.Fatalf("RunPostToolCall error = %T, want HookError", err)
	}
	if hookErr.Code != ErrorCodeHookFailed {
		t.Fatalf("HookError.Code = %q, want %s", hookErr.Code, ErrorCodeHookFailed)
	}
}

func TestRunnerProtocolErrorsDoNotEchoHookValues(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{{
			HookEventName: "Jane Doe raw body",
			Decision:      DecisionContinue,
		}},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:        "privacy-filter",
		FailureMode: "fail_closed",
	}), caller)

	_, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err == nil {
		t.Fatal("RunPostToolCall returned nil error, want HookError")
	}
	var hookErr *HookError
	if !errors.As(err, &hookErr) {
		t.Fatalf("RunPostToolCall error = %T, want HookError", err)
	}
	if strings.Contains(hookErr.Message, "Jane Doe raw body") {
		t.Fatalf("HookError.Message = %q, must not echo hook value", hookErr.Message)
	}
	if strings.Contains(string(hookErr.FiltersApplied), "Jane Doe raw body") {
		t.Fatalf("FiltersApplied = %s, must not echo hook value", hookErr.FiltersApplied)
	}
}

func TestRunnerProtocolErrorsDoNotEchoInvalidDecision(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{{
			HookEventName: EventGatewayPostToolCall,
			Decision:      "Jane Doe raw decision",
		}},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:        "privacy-filter",
		FailureMode: "fail_closed",
	}), caller)

	_, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err == nil {
		t.Fatal("RunPostToolCall returned nil error, want HookError")
	}
	var hookErr *HookError
	if !errors.As(err, &hookErr) {
		t.Fatalf("RunPostToolCall error = %T, want HookError", err)
	}
	if strings.Contains(hookErr.Message, "Jane Doe raw decision") {
		t.Fatalf("HookError.Message = %q, must not echo invalid decision", hookErr.Message)
	}
	filters := string(hookErr.FiltersApplied)
	if strings.Contains(filters, "Jane Doe raw decision") {
		t.Fatalf("FiltersApplied = %s, must not echo invalid decision", filters)
	}
	if !strings.Contains(filters, `"decision":"invalid"`) {
		t.Fatalf("FiltersApplied = %s, want normalized invalid decision", filters)
	}
}

func TestRunnerSanitizesAuditMetadataStrings(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{{
			HookEventName: EventGatewayPostToolCall,
			Decision:      DecisionContinue,
			AuditMetadata: map[string]any{
				"patient": "Jane Doe raw body",
				"score":   42,
				"allowed": true,
				"nested": map[string]any{
					"token": "Jane Doe raw body",
					"count": 7,
				},
				"items": []any{"Jane Doe raw body", false, 3.5},
			},
		}},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:        "privacy-filter",
		FailureMode: "fail_closed",
	}), caller)

	result, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err != nil {
		t.Fatalf("RunPostToolCall returned error: %v", err)
	}
	filters := string(result.FiltersApplied)
	if strings.Contains(filters, "Jane Doe raw body") {
		t.Fatalf("FiltersApplied = %s, must not include raw metadata string", filters)
	}
	if !strings.Contains(filters, "[omitted]") {
		t.Fatalf("FiltersApplied = %s, want omitted string marker", filters)
	}
	if !strings.Contains(filters, `42`) || !strings.Contains(filters, `true`) || !strings.Contains(filters, `7`) {
		t.Fatalf("FiltersApplied = %s, want aggregate-safe metadata values preserved", filters)
	}
}

func TestRunnerSanitizesAuditMetadataKeys(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{{
			HookEventName: EventGatewayPostToolCall,
			Decision:      DecisionContinue,
			AuditMetadata: map[string]any{
				"Jane Doe raw key": 42,
				"nested": map[string]any{
					"Jane Doe nested key": 7,
				},
			},
		}},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:        "privacy-filter",
		FailureMode: "fail_closed",
	}), caller)

	result, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err != nil {
		t.Fatalf("RunPostToolCall returned error: %v", err)
	}
	filters := string(result.FiltersApplied)
	if strings.Contains(filters, "Jane Doe raw key") {
		t.Fatalf("FiltersApplied = %s, must not include raw metadata key", filters)
	}
	if strings.Contains(filters, "Jane Doe nested key") {
		t.Fatalf("FiltersApplied = %s, must not include raw nested metadata key", filters)
	}
	if !strings.Contains(filters, `"field_0"`) {
		t.Fatalf("FiltersApplied = %s, want generic metadata field key", filters)
	}
}

func TestRunnerUnauthorizedMutationFailsClosedEvenWhenFailOpen(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{{
			HookEventName: EventGatewayPostToolCall,
			Decision:      DecisionContinue,
			UpdatedToolResponse: &adapters.Result{
				Summary: "redacted",
			},
		}},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:        "privacy-filter",
		FailureMode: "fail_open",
	}), caller)

	_, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err == nil {
		t.Fatal("RunPostToolCall returned nil error, want HookError")
	}
	var hookErr *HookError
	if !errors.As(err, &hookErr) {
		t.Fatalf("RunPostToolCall error = %T, want HookError", err)
	}
	if hookErr.Code != ErrorCodeHookFailed {
		t.Fatalf("HookError.Code = %q, want %s", hookErr.Code, ErrorCodeHookFailed)
	}
	if !hookErr.SkipChainExtraction {
		t.Fatal("HookError.SkipChainExtraction = false, want true")
	}
}

func TestRunnerFailOpenSkipsChainExtraction(t *testing.T) {
	raw := &adapters.Result{Summary: "raw"}
	caller := &fakeCaller{
		errs: []error{errors.New("hook unavailable")},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:        "privacy-filter",
		FailureMode: "fail_open",
	}), caller)

	result, err := runner.RunPostToolCall(context.Background(), runnerEvent(raw))
	if err != nil {
		t.Fatalf("RunPostToolCall returned error: %v", err)
	}
	if result.ToolResponse != raw {
		t.Fatalf("ToolResponse = %#v, want original raw response", result.ToolResponse)
	}
	if !result.SkipChainExtraction {
		t.Fatal("SkipChainExtraction = false, want true")
	}
}

func TestRunnerBlockAlwaysBlocks(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{{
			HookEventName: EventGatewayPostToolCall,
			Decision:      DecisionBlock,
		}},
	}
	runner := NewRunner(runnerConfig(config.GatewayHookHandlerConfig{
		Name:        "privacy-filter",
		FailureMode: "fail_open",
	}), caller)

	_, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err == nil {
		t.Fatal("RunPostToolCall returned nil error, want HookError")
	}
	var hookErr *HookError
	if !errors.As(err, &hookErr) {
		t.Fatalf("RunPostToolCall error = %T, want HookError", err)
	}
	if hookErr.Code != ErrorCodeHookBlocked {
		t.Fatalf("HookError.Code = %q, want %s", hookErr.Code, ErrorCodeHookBlocked)
	}
	if !hookErr.SkipChainExtraction {
		t.Fatal("HookError.SkipChainExtraction = false, want true")
	}
}

func TestRunnerRunsMatchingHandlersInOrder(t *testing.T) {
	caller := &fakeCaller{
		responses: []HookResponse{
			{
				HookEventName: EventGatewayPostToolCall,
				Decision:      DecisionContinue,
				UpdatedToolResponse: &adapters.Result{
					Summary: "first-redacted",
				},
			},
			{
				HookEventName: EventGatewayPostToolCall,
				Decision:      DecisionContinue,
			},
		},
	}
	cfg := runnerConfig(
		config.GatewayHookHandlerConfig{
			Name:                "first-filter",
			FailureMode:         "fail_closed",
			AllowResponseUpdate: true,
		},
		config.GatewayHookHandlerConfig{
			Name:                "second-filter",
			FailureMode:         "fail_closed",
			AllowResponseUpdate: true,
		},
	)
	runner := NewRunner(cfg, caller)

	result, err := runner.RunPostToolCall(context.Background(), runnerEvent(&adapters.Result{Summary: "raw"}))
	if err != nil {
		t.Fatalf("RunPostToolCall returned error: %v", err)
	}
	if got := len(caller.seen); got != 2 {
		t.Fatalf("hook calls = %d, want 2", got)
	}
	if got := caller.seen[0].ToolResponse.Summary; got != "raw" {
		t.Fatalf("first ToolResponse.Summary = %q, want raw", got)
	}
	if got := caller.seen[1].ToolResponse.Summary; got != "first-redacted" {
		t.Fatalf("second ToolResponse.Summary = %q, want first-redacted", got)
	}
	if got := result.ToolResponse.Summary; got != "first-redacted" {
		t.Fatalf("final ToolResponse.Summary = %q, want first-redacted", got)
	}
}

func runnerConfig(handlers ...config.GatewayHookHandlerConfig) config.GatewayHooksConfig {
	return config.GatewayHooksConfig{
		Enabled: true,
		Events: map[string][]config.GatewayHookEventConfig{
			EventGatewayPostToolCall: {{
				Matcher: config.GatewayHookMatcherConfig{
					Service: "google.gmail",
					Action:  "get_message",
				},
				Handlers: handlers,
			}},
		},
	}
}

func runnerEvent(result *adapters.Result) PostToolCallEvent {
	return PostToolCallEvent{
		RequestID:    "req-123",
		AuditID:      "audit-123",
		UserID:       "user-123",
		AgentID:      "agent-123",
		TaskID:       "task-123",
		SessionID:    "session-123",
		Service:      "google.gmail",
		Action:       "get_message",
		Params:       map[string]any{"message_id": "msg-123"},
		Reason:       "read message",
		ToolResponse: result,
	}
}

func assertFiltersAppliedValidJSON(t *testing.T, raw json.RawMessage) {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("FiltersApplied is empty")
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("FiltersApplied is invalid JSON: %v", err)
	}
	if _, ok := decoded["gateway_hooks"]; !ok {
		t.Fatalf("FiltersApplied = %s, want gateway_hooks", raw)
	}
}
