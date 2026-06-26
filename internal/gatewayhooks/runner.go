package gatewayhooks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/clawvisor/clawvisor/pkg/config"
)

type Caller interface {
	Call(ctx context.Context, cfg config.GatewayHookHandlerConfig, req HookRequest) (HookResponse, HandlerSummary, error)
}

type Runner struct {
	cfg    config.GatewayHooksConfig
	caller Caller
}

func NewRunner(cfg config.GatewayHooksConfig, caller Caller) *Runner {
	if caller == nil {
		caller = NewHTTPClient(nil)
	}
	return &Runner{cfg: cfg, caller: caller}
}

func (r *Runner) RunPostToolCall(ctx context.Context, event PostToolCallEvent) (*RunResult, error) {
	current := event.ToolResponse
	if r == nil || !r.cfg.Enabled || current == nil {
		return &RunResult{ToolResponse: current}, nil
	}

	entries := r.cfg.Events[EventGatewayPostToolCall]
	summaries := []HandlerSummary{}
	for _, entry := range entries {
		if !MatchGatewayCall(entry.Matcher, event.Service, event.Action) {
			continue
		}
		for _, handler := range entry.Handlers {
			service := normalizeService(event.Service)
			req := HookRequest{
				HookEventName: EventGatewayPostToolCall,
				HookName:      handler.Name,
				RequestID:     event.RequestID,
				AuditID:       event.AuditID,
				UserID:        event.UserID,
				AgentID:       event.AgentID,
				TaskID:        event.TaskID,
				SessionID:     event.SessionID,
				Service:       service,
				Action:        event.Action,
				ToolName:      service + "." + event.Action,
				ToolInput: ToolInput{
					Params: event.Params,
					Reason: event.Reason,
				},
				ToolResponse: current,
			}
			resp, summary, err := r.caller.Call(ctx, handler, req)
			summary = normalizeHandlerSummary(summary, handler)
			if err != nil {
				summary.Error = err.Error()
				summaries = append(summaries, summary)
				filters := marshalFiltersApplied(summaries)
				if normalizedFailureMode(handler.FailureMode) == "fail_open" {
					return &RunResult{ToolResponse: current, FiltersApplied: filters, SkipChainExtraction: true}, nil
				}
				return nil, &HookError{
					Code:                ErrorCodeHookFailed,
					Message:             err.Error(),
					FiltersApplied:      filters,
					SkipChainExtraction: true,
				}
			}

			if err := validateHookResponse(resp, handler); err != nil {
				summary.Error = err.Error()
				summaries = append(summaries, summary)
				filters := marshalFiltersApplied(summaries)
				validationErr, isValidationErr := err.(*hookResponseValidationError)
				forceFailClosed := isValidationErr && validationErr.forceFailClosed
				if normalizedFailureMode(handler.FailureMode) == "fail_open" && !forceFailClosed {
					return &RunResult{ToolResponse: current, FiltersApplied: filters, SkipChainExtraction: true}, nil
				}
				return nil, &HookError{
					Code:                ErrorCodeHookFailed,
					Message:             err.Error(),
					FiltersApplied:      filters,
					SkipChainExtraction: true,
				}
			}

			summaries = append(summaries, summary)
			filters := marshalFiltersApplied(summaries)
			if resp.Decision == DecisionBlock {
				return nil, &HookError{
					Code:                ErrorCodeHookBlocked,
					Message:             fmt.Sprintf("hook %q blocked request", handler.Name),
					FiltersApplied:      filters,
					SkipChainExtraction: true,
				}
			}
			if resp.UpdatedToolResponse != nil {
				current = resp.UpdatedToolResponse
			}
		}
	}

	return &RunResult{
		ToolResponse:        current,
		FiltersApplied:      marshalFiltersApplied(summaries),
		SkipChainExtraction: false,
	}, nil
}

type hookResponseValidationError struct {
	message         string
	forceFailClosed bool
}

func (e *hookResponseValidationError) Error() string {
	return e.message
}

func validateHookResponse(resp HookResponse, handler config.GatewayHookHandlerConfig) error {
	if resp.HookEventName != EventGatewayPostToolCall {
		return &hookResponseValidationError{
			message: fmt.Sprintf("hook %q returned invalid hook_event_name", handler.Name),
		}
	}
	if resp.Decision != DecisionContinue && resp.Decision != DecisionBlock {
		return &hookResponseValidationError{
			message: fmt.Sprintf("hook %q returned invalid decision", handler.Name),
		}
	}
	if resp.UpdatedToolResponse != nil && !handler.AllowResponseUpdate {
		return &hookResponseValidationError{
			message:         fmt.Sprintf("hook %q returned updated_tool_response without allow_response_update", handler.Name),
			forceFailClosed: true,
		}
	}
	return nil
}

func marshalFiltersApplied(summaries []HandlerSummary) json.RawMessage {
	if len(summaries) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{
		"gateway_hooks": map[string]any{
			EventGatewayPostToolCall: summaries,
		},
	})
	if err != nil {
		return nil
	}
	return body
}

func normalizeHandlerSummary(summary HandlerSummary, handler config.GatewayHookHandlerConfig) HandlerSummary {
	if summary.Name == "" {
		summary.Name = handler.Name
	}
	switch summary.Decision {
	case "", DecisionContinue, DecisionBlock:
	default:
		summary.Decision = "invalid"
	}
	summary.FailureMode = normalizedFailureMode(handler.FailureMode)
	summary.Metadata = sanitizeAuditMetadata(summary.Metadata)
	return summary
}

func sanitizeAuditMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	sanitized := make(map[string]any, len(metadata))
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for idx, key := range keys {
		sanitized[fmt.Sprintf("field_%d", idx)] = sanitizeAuditMetadataValue(metadata[key])
	}
	return sanitized
}

func sanitizeAuditMetadataValue(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case bool:
		return typed
	case int:
		return typed
	case int8:
		return typed
	case int16:
		return typed
	case int32:
		return typed
	case int64:
		return typed
	case uint:
		return typed
	case uint8:
		return typed
	case uint16:
		return typed
	case uint32:
		return typed
	case uint64:
		return typed
	case float32:
		return typed
	case float64:
		return typed
	case json.Number:
		return typed
	case map[string]any:
		return sanitizeAuditMetadata(typed)
	case []any:
		sanitized := make([]any, len(typed))
		for idx, item := range typed {
			sanitized[idx] = sanitizeAuditMetadataValue(item)
		}
		return sanitized
	default:
		return "[omitted]"
	}
}
