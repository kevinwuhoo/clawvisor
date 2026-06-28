package api_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/clawvisor/clawvisor/pkg/config"
	"github.com/clawvisor/clawvisor/pkg/store"
)

func newGatewayHookServer(t *testing.T, secret string, response map[string]any) (*httptest.Server, <-chan map[string]any) {
	t.Helper()
	seen := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readHookBody(t, r)
		if secret != "" {
			ts := r.Header.Get("X-Clawvisor-Hook-Timestamp")
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(ts + "."))
			mac.Write(body)
			want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if r.Header.Get("X-Clawvisor-Hook-Signature") != want {
				http.Error(w, "bad signature", http.StatusUnauthorized)
				return
			}
		}
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seen <- req
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func readHookBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read hook body: %v", err)
	}
	return body
}

func configureGatewayHook(t *testing.T, hookURL, secretEnv string) func(*config.Config) {
	t.Helper()
	return func(cfg *config.Config) {
		cfg.GatewayHooks = config.GatewayHooksConfig{
			Enabled: true,
			Events: map[string][]config.GatewayHookEventConfig{
				"GatewayPostToolCall": {{
					Matcher: config.GatewayHookMatcherConfig{Service: "mock.hook", Action: "run"},
					Handlers: []config.GatewayHookHandlerConfig{{
						Name: "privacy-filter", Type: "http", URL: hookURL, TimeoutSeconds: 5,
						FailureMode: "fail_closed", AllowResponseUpdate: true, SecretEnv: secretEnv,
					}},
				}},
			},
		}
	}
}

func TestGatewayExternalHook_RedactsAutoExecuteResponse(t *testing.T) {
	secret := "hook-secret"
	t.Setenv("CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET", secret)
	hookSrv, seen := newGatewayHookServer(t, secret, map[string]any{
		"hook_event_name": "GatewayPostToolCall",
		"decision":        "continue",
		"updated_tool_response": map[string]any{
			"summary": "Email from [PRIVATE_PERSON]",
			"data":    map[string]any{"body": "hello [PRIVATE_PERSON]"},
		},
		"audit_metadata": map[string]any{
			"privacy_filter": map[string]any{"applied": true, "items_redacted": 2},
		},
	})
	adapter := newMockAdapter("mock.hook", "run").withResult("Email from Jane Doe", map[string]any{"body": "hello Jane Doe"})
	env := newTestEnvWithConfig(t, config.LLMConfig{}, nil, configureGatewayHook(t, hookSrv.URL, "CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET"), adapter)
	sc := newScenario(t, env, "hook")
	taskID := sc.createApprovedTask(t, env, "mock.hook", "run", true)
	reqID := fmt.Sprintf("hook-auto-%s", randSuffix())

	result := sc.gatewayRequestWithTask(env, reqID, "mock.hook", "run", taskID)
	if result["status"] != "executed" {
		t.Fatalf("status = %v", result["status"])
	}
	body := fmt.Sprintf("%v", result["result"])
	if bodyContainsRaw := body == "" || containsAll(body, "Jane Doe"); bodyContainsRaw {
		t.Fatalf("raw result leaked: %s", body)
	}
	if !containsAll(body, "[PRIVATE_PERSON]") {
		t.Fatalf("redacted result missing marker: %s", body)
	}
	select {
	case req := <-seen:
		if req["tool_name"] != "mock.hook.run" {
			t.Fatalf("tool_name = %v", req["tool_name"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hook request not received")
	}
	entries, _, err := env.Store.ListAuditEntries(context.Background(), sc.session.UserID, store.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.RequestID == reqID && len(e.FiltersApplied) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected audit filters_applied for hook request")
	}
}

func TestGatewayExternalHook_RedactsCallbackPayload(t *testing.T) {
	t.Setenv("CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET", "hook-secret")
	hookSrv, _ := newGatewayHookServer(t, "hook-secret", map[string]any{
		"hook_event_name": "GatewayPostToolCall",
		"decision":        "continue",
		"updated_tool_response": map[string]any{
			"summary": "Callback [PRIVATE_PERSON]",
			"data":    map[string]any{"body": "[PRIVATE_PERSON]"},
		},
	})
	adapter := newMockAdapter("mock.hook", "run").withResult("Callback Jane Doe", map[string]any{"body": "Jane Doe"})
	env := newTestEnvWithConfig(t, config.LLMConfig{}, nil, configureGatewayHook(t, hookSrv.URL, "CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET"), adapter)
	sc := newScenario(t, env, "hook-callback")
	taskID := sc.createApprovedTask(t, env, "mock.hook", "run", true)
	cbSrv, cbCh := newCallbackServer(t)
	reqID := fmt.Sprintf("hook-callback-%s", randSuffix())

	resp := env.do("POST", "/api/gateway/request", sc.AgentToken, map[string]any{
		"service": "mock.hook", "action": "run", "params": map[string]any{},
		"reason": "callback hook", "request_id": reqID, "task_id": taskID,
		"context": map[string]any{"callback_url": cbSrv.URL + "/inbound"},
	})
	mustStatus(t, resp, http.StatusOK)

	select {
	case cb := <-cbCh:
		payload := string(cb.body)
		if strings.Contains(payload, "Jane Doe") {
			t.Fatalf("raw callback leaked: %s", payload)
		}
		var decoded map[string]any
		if err := json.Unmarshal(cb.body, &decoded); err != nil {
			t.Fatalf("callback body not JSON: %v", err)
		}
		if decoded["status"] != "executed" {
			t.Fatalf("callback status = %v, want executed", decoded["status"])
		}
		result := nested(t, decoded, "result")
		if got := str(t, result, "summary"); got != "Callback [PRIVATE_PERSON]" {
			t.Fatalf("callback result summary = %q, want redacted summary", got)
		}
		data := nested(t, result, "data")
		if got := str(t, data, "body"); got != "[PRIVATE_PERSON]" {
			t.Fatalf("callback result data.body = %q, want redacted body", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("callback not received")
	}
}

func TestGatewayExternalHook_FailClosedDoesNotReturnRawResult(t *testing.T) {
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "offline", http.StatusBadGateway)
	}))
	t.Cleanup(hookSrv.Close)
	adapter := newMockAdapter("mock.hook", "run").withResult("Jane Doe raw", map[string]any{"body": "Jane Doe"})
	env := newTestEnvWithConfig(t, config.LLMConfig{}, nil, configureGatewayHook(t, hookSrv.URL, ""), adapter)
	sc := newScenario(t, env, "hook-fail")
	taskID := sc.createApprovedTask(t, env, "mock.hook", "run", true)
	result := sc.gatewayRequestWithTask(env, fmt.Sprintf("hook-fail-%s", randSuffix()), "mock.hook", "run", taskID)
	if result["status"] != "error" {
		t.Fatalf("status = %v, want error", result["status"])
	}
	if result["code"] != "HOOK_FAILED" {
		t.Fatalf("code = %v, want HOOK_FAILED", result["code"])
	}
	if strings.Contains(fmt.Sprintf("%v", result), "Jane Doe") {
		t.Fatalf("raw result leaked on hook failure: %#v", result)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
