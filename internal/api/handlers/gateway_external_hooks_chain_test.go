package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/clawvisor/clawvisor/internal/gatewayhooks"
	"github.com/clawvisor/clawvisor/internal/intent"
	"github.com/clawvisor/clawvisor/pkg/adapters"
	"github.com/clawvisor/clawvisor/pkg/store"
)

type redactingPostToolCallRunner struct{}

func (redactingPostToolCallRunner) RunPostToolCall(_ context.Context, _ gatewayhooks.PostToolCallEvent) (*gatewayhooks.RunResult, error) {
	return &gatewayhooks.RunResult{
		ToolResponse: &adapters.Result{Summary: "redacted summary", Data: map[string]any{"id": "redacted-id"}},
	}, nil
}

func TestGatewayExternalHook_ChainExtractionSeesUpdatedResult(t *testing.T) {
	st := newLocalTestStore()
	st.tasks["task-1"] = &store.Task{
		ID: "task-1", UserID: "user-1", AgentID: "agent-1", Status: "active",
		AuthorizedActions: []store.TaskAction{{Service: "local.files", Action: "read_file", AutoExecute: true}},
	}
	provider := &mockLocalProvider{services: testServices()}
	executor := &mockLocalExecutor{result: &adapters.Result{Summary: "raw summary", Data: map[string]any{"id": "raw-id"}}}
	verifier := &mockVerifier{verdict: &intent.VerificationVerdict{
		Allow: true, ParamScope: "ok", ReasonCoherence: "ok", ExtractContext: true,
	}}
	extractor := newRecordingExtractor()
	h := newGatewayHandlerWithRecordingExtractor(st, provider, executor, verifier, extractor)
	h.SetPostToolCallHookRunner(redactingPostToolCallRunner{})

	w := makeGatewayRequest(t, h, map[string]any{
		"service": "local.files", "action": "read_file", "reason": "read the file",
		"task_id": "task-1", "params": map[string]any{"path": "/tmp/notes.txt"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	extractor.waitForExtraction(t)
	if extractor.builtinCallCount() != 1 {
		t.Fatalf("ExtractBuiltins calls = %d, want 1", extractor.builtinCallCount())
	}
	resultSeenByExtractor := extractor.lastBuiltinResultValue()
	if strings.Contains(resultSeenByExtractor, "raw summary") || strings.Contains(resultSeenByExtractor, "raw-id") {
		t.Fatalf("chain extraction saw raw result: %q", resultSeenByExtractor)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(resultSeenByExtractor), &decoded); err != nil {
		t.Fatalf("chain extraction result is not JSON: %v", err)
	}
	if got := decoded["summary"]; got != "redacted summary" {
		t.Fatalf("chain extraction summary = %v, want redacted summary", got)
	}
	data, ok := decoded["data"].(map[string]any)
	if !ok {
		t.Fatalf("chain extraction data is not an object: %T", decoded["data"])
	}
	if got := data["id"]; got != "redacted-id" {
		t.Fatalf("chain extraction data.id = %v, want redacted-id", got)
	}
}
