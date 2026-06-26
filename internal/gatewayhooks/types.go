package gatewayhooks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/clawvisor/clawvisor/pkg/adapters"
)

const (
	EventGatewayPostToolCall = "GatewayPostToolCall"

	DecisionContinue = "continue"
	DecisionBlock    = "block"

	ErrorCodeHookFailed  = "HOOK_FAILED"
	ErrorCodeHookBlocked = "HOOK_BLOCKED"
)

type ToolInput struct {
	Params map[string]any `json:"params,omitempty"`
	Reason string         `json:"reason,omitempty"`
}

type HookRequest struct {
	HookEventName string           `json:"hook_event_name"`
	HookName      string           `json:"hook_name"`
	RequestID     string           `json:"request_id,omitempty"`
	AuditID       string           `json:"audit_id,omitempty"`
	UserID        string           `json:"user_id,omitempty"`
	AgentID       string           `json:"agent_id,omitempty"`
	TaskID        string           `json:"task_id,omitempty"`
	SessionID     string           `json:"session_id,omitempty"`
	Service       string           `json:"service"`
	Action        string           `json:"action"`
	ToolName      string           `json:"tool_name"`
	ToolInput     ToolInput        `json:"tool_input"`
	ToolResponse  *adapters.Result `json:"tool_response"`
}

type HookResponse struct {
	HookEventName       string           `json:"hook_event_name"`
	Decision            string           `json:"decision"`
	UpdatedToolResponse *adapters.Result `json:"updated_tool_response,omitempty"`
	AuditMetadata       map[string]any   `json:"audit_metadata,omitempty"`
}

type PostToolCallEvent struct {
	RequestID    string
	AuditID      string
	UserID       string
	AgentID      string
	TaskID       string
	SessionID    string
	Service      string
	Action       string
	Params       map[string]any
	Reason       string
	ToolResponse *adapters.Result
}

type HandlerSummary struct {
	Name                string         `json:"name"`
	Decision            string         `json:"decision"`
	DurationMS          int64          `json:"duration_ms"`
	UpdatedToolResponse bool           `json:"updated_tool_response,omitempty"`
	FailureMode         string         `json:"failure_mode,omitempty"`
	Error               string         `json:"error,omitempty"`
	Metadata            map[string]any `json:"metadata,omitempty"`
}

type RunResult struct {
	ToolResponse        *adapters.Result
	FiltersApplied      json.RawMessage
	SkipChainExtraction bool
}

type PostToolCallRunner interface {
	RunPostToolCall(ctx context.Context, event PostToolCallEvent) (*RunResult, error)
}

type HookError struct {
	Code                string
	Message             string
	FiltersApplied      json.RawMessage
	SkipChainExtraction bool
}

func (e *HookError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}
