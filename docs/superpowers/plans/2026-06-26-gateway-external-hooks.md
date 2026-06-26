# Gateway External Hooks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic external HTTP hook system for native gateway adapter results, with `GatewayPostToolCall` as the first event and privacy filtering supported as an external hook service.

**Architecture:** Clawvisor core parses `gateway_hooks` config, constructs an `internal/gatewayhooks` runner, and invokes matching HTTP hooks after successful adapter execution but before HTTP responses, callbacks, or chain extraction. Hook services receive signed JSON, may return an updated `adapters.Result`, and Clawvisor persists aggregate hook metadata in `audit_log.filters_applied`.

**Tech Stack:** Go 1.25+, standard `net/http`, `crypto/hmac`, `crypto/sha256`, existing Clawvisor config/store/gateway packages, SQLite/Postgres store implementations.

---

## Scope Decisions

- Implement only the core Clawvisor hook system in this repository.
- Do not add OpenAI Privacy Filter dependencies to Clawvisor.
- Do not implement the companion privacy-filter sidecar in this plan.
- Preserve the existing cloud/enterprise `GatewayHooks.BeforeAuthorize` API. The new external HTTP hook system lives in `internal/gatewayhooks` and is wired separately.
- Return gateway hook execution errors as gateway response bodies with `status: "error"` and `code: "HOOK_FAILED"` or `code: "HOOK_BLOCKED"`.
- For hook failures after adapter execution, update the audit row to `outcome="error"` and do not return the raw adapter result when the hook blocks or fails closed.

## File Structure

Core hook package:

- Create `internal/gatewayhooks/types.go`: event/request/response DTOs, constants, typed errors, runner interface.
- Create `internal/gatewayhooks/matcher.go`: service/action matcher logic.
- Create `internal/gatewayhooks/http_client.go`: HTTP POST handler client and HMAC signing.
- Create `internal/gatewayhooks/runner.go`: ordered matching, handler execution, mutation/failure/audit summary logic.
- Create `internal/gatewayhooks/matcher_test.go`: matcher unit tests.
- Create `internal/gatewayhooks/http_client_test.go`: HMAC, timeout, status, and schema tests.
- Create `internal/gatewayhooks/runner_test.go`: fail-open, fail-closed, block, mutation permission, ordered execution tests.

Config and error codes:

- Modify `pkg/config/config.go`: add `GatewayHooksConfig`, defaults, env JSON override, validation.
- Modify `pkg/config/config_test.go`: add config and validation tests.
- Modify `pkg/gateway/errorcodes.go`: add `CodeHookFailed` and `CodeHookBlocked`.

Audit persistence:

- Modify `pkg/store/store.go`: add `UpdateAuditFiltersApplied`.
- Modify `pkg/store/sqlite/store.go`: implement `UpdateAuditFiltersApplied`.
- Modify `pkg/store/postgres/store.go`: implement `UpdateAuditFiltersApplied`.
- Modify `pkg/store/sqlite/sqlite_test.go`: add a focused audit filter update test.
- Modify `internal/api/handlers/local_service_test.go`: add the method to the test store.

Server and handlers:

- Modify `internal/api/server.go`: construct the external hook runner and pass it to handlers.
- Modify `internal/api/handlers/gateway.go`: add runner field, setter, helper, and auto-execute / approved-execute hook calls.
- Modify `internal/api/handlers/approvals.go`: add runner field, setter, hook approved callback execution.
- Modify `internal/api/handlers/services.go`: add runner field, setter, hook pending activation re-execution.
- Add `internal/api/gateway_external_hooks_test.go`: end-to-end API tests for response, callback, fail-closed, and audit metadata.
- Add `internal/api/handlers/gateway_external_hooks_chain_test.go`: handler-level test proving chain extraction sees the hook-updated result.

Docs:

- Modify `docs/ARCHITECTURE.md`: mention gateway external hook step.
- Add `docs/GATEWAY_HOOKS.md`: operator-facing hook protocol documentation.
- Modify `AGENTS.md`: mark gateway hooks as security-sensitive.

## Task 0: Unblock Verification Toolchain

**Files:**
- No repo files changed.

- [ ] **Step 1: Check host Go**

Run:

```bash
go version
```

Expected when ready:

```text
go version go1.25
```

Any `go1.25.x` or newer is acceptable. In the current shell, `go` is not on `PATH`; this task remains blocked until Go is installed or a Docker-based test workflow is explicitly approved.

- [ ] **Step 2: Run baseline tests**

Run:

```bash
go test ./...
```

Expected: all packages pass or skip. If this fails before code changes, stop and record the failing packages as baseline failures.

- [ ] **Step 3: Commit nothing**

Do not commit after this task. This task only establishes baseline verification.

## Task 1: Add Gateway Hook Config And Error Codes

**Files:**
- Modify: `pkg/config/config.go`
- Modify: `pkg/config/config_test.go`
- Modify: `pkg/gateway/errorcodes.go`

- [ ] **Step 1: Write failing config tests**

Append these tests to `pkg/config/config_test.go`:

```go
func TestGatewayHooksDefaults(t *testing.T) {
	cfg := Default()
	if cfg.GatewayHooks.Enabled {
		t.Fatal("gateway hooks should default to disabled")
	}
	if len(cfg.GatewayHooks.Events) != 0 {
		t.Fatalf("gateway hook events default = %#v, want empty", cfg.GatewayHooks.Events)
	}
}

func TestGatewayHooksYAMLAndEnvJSON(t *testing.T) {
	t.Setenv("CLAWVISOR_GATEWAY_HOOKS_JSON", `{
	  "enabled": true,
	  "events": {
	    "GatewayPostToolCall": [{
	      "matcher": {"service": "google.gmail", "action": "get_message|list_messages"},
	      "handlers": [{
	        "name": "privacy-filter",
	        "type": "http",
	        "url": "http://127.0.0.1:8765/v1/hooks/gateway/post-tool-call",
	        "timeout_seconds": 7,
	        "failure_mode": "fail_closed",
	        "allow_response_update": true,
	        "secret_env": "CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET"
	      }]
	    }]
	  }
	}`)
	t.Setenv("CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET", "test-secret")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.GatewayHooks.Enabled {
		t.Fatal("expected gateway hooks enabled from env JSON")
	}
	entries := cfg.GatewayHooks.Events["GatewayPostToolCall"]
	if len(entries) != 1 {
		t.Fatalf("GatewayPostToolCall entries = %d, want 1", len(entries))
	}
	got := entries[0].Handlers[0]
	if got.Name != "privacy-filter" {
		t.Fatalf("handler name = %q, want privacy-filter", got.Name)
	}
	if got.TimeoutSeconds != 7 {
		t.Fatalf("timeout = %d, want 7", got.TimeoutSeconds)
	}
	if !got.AllowResponseUpdate {
		t.Fatal("expected allow_response_update=true")
	}
}

func TestValidateGatewayHooksRejectsMissingSecretEnv(t *testing.T) {
	cfg := Default()
	cfg.GatewayHooks = GatewayHooksConfig{
		Enabled: true,
		Events: map[string][]GatewayHookEventConfig{
			"GatewayPostToolCall": {{
				Matcher: GatewayHookMatcherConfig{Service: "google.gmail", Action: "get_message"},
				Handlers: []GatewayHookHandlerConfig{{
					Name:           "privacy-filter",
					Type:           "http",
					URL:            "http://127.0.0.1:8765/hook",
					TimeoutSeconds: 10,
					FailureMode:    "fail_closed",
					SecretEnv:      "CLAWVISOR_MISSING_HOOK_SECRET",
				}},
			}},
		},
	}
	t.Setenv("CLAWVISOR_MISSING_HOOK_SECRET", "")

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "CLAWVISOR_MISSING_HOOK_SECRET") {
		t.Fatalf("expected missing hook secret validation error, got %v", err)
	}
}
```

- [ ] **Step 2: Run config tests and confirm failure**

Run:

```bash
go test ./pkg/config -run 'TestGatewayHooks' -count=1
```

Expected: compile failure because `Config.GatewayHooks` and related types do not exist.

- [ ] **Step 3: Add config structs**

In `pkg/config/config.go`, add this field to `Config`:

```go
GatewayHooks GatewayHooksConfig `yaml:"gateway_hooks" json:"gateway_hooks"`
```

Add these types near `GatewayConfig`:

```go
// GatewayHooksConfig controls external HTTP hooks around native gateway events.
type GatewayHooksConfig struct {
	Enabled bool                                `yaml:"enabled" json:"enabled"`
	Events  map[string][]GatewayHookEventConfig `yaml:"events" json:"events"`
}

// GatewayHookEventConfig is one matcher plus one or more handlers for an event.
type GatewayHookEventConfig struct {
	Matcher  GatewayHookMatcherConfig   `yaml:"matcher" json:"matcher"`
	Handlers []GatewayHookHandlerConfig `yaml:"handlers" json:"handlers"`
}

// GatewayHookMatcherConfig selects gateway calls by normalized service and action.
type GatewayHookMatcherConfig struct {
	Service string `yaml:"service" json:"service"`
	Action  string `yaml:"action" json:"action"`
}

// GatewayHookHandlerConfig defines one external hook handler.
type GatewayHookHandlerConfig struct {
	Name                string `yaml:"name" json:"name"`
	Type                string `yaml:"type" json:"type"`
	URL                 string `yaml:"url" json:"url"`
	TimeoutSeconds      int    `yaml:"timeout_seconds" json:"timeout_seconds"`
	FailureMode         string `yaml:"failure_mode" json:"failure_mode"`
	AllowResponseUpdate bool   `yaml:"allow_response_update" json:"allow_response_update"`
	SecretEnv           string `yaml:"secret_env" json:"secret_env"`
}
```

- [ ] **Step 4: Add defaults and env JSON override**

In `Default()`, initialize the new field:

```go
GatewayHooks: GatewayHooksConfig{
	Enabled: false,
	Events:  map[string][]GatewayHookEventConfig{},
},
```

In `Load`, after the existing gateway/NPS env override block, add:

```go
if v := os.Getenv("CLAWVISOR_GATEWAY_HOOKS_JSON"); strings.TrimSpace(v) != "" {
	var hooks GatewayHooksConfig
	if err := yaml.Unmarshal([]byte(v), &hooks); err != nil {
		return nil, fmt.Errorf("parsing CLAWVISOR_GATEWAY_HOOKS_JSON: %w", err)
	}
	cfg.GatewayHooks = hooks
}
```

- [ ] **Step 5: Add validation**

In `pkg/config/config.go`, add this method:

```go
func (c GatewayHooksConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	for eventName, entries := range c.Events {
		if eventName != "GatewayPostToolCall" {
			return fmt.Errorf("gateway_hooks event %q is not supported", eventName)
		}
		for i, entry := range entries {
			if strings.TrimSpace(entry.Matcher.Service) == "" {
				return fmt.Errorf("gateway_hooks.%s[%d].matcher.service must be set", eventName, i)
			}
			if strings.TrimSpace(entry.Matcher.Action) == "" {
				return fmt.Errorf("gateway_hooks.%s[%d].matcher.action must be set", eventName, i)
			}
			if len(entry.Handlers) == 0 {
				return fmt.Errorf("gateway_hooks.%s[%d].handlers must contain at least one handler", eventName, i)
			}
			for j, handler := range entry.Handlers {
				if strings.TrimSpace(handler.Name) == "" {
					return fmt.Errorf("gateway_hooks.%s[%d].handlers[%d].name must be set", eventName, i, j)
				}
				if handler.Type != "http" {
					return fmt.Errorf("gateway_hooks.%s[%d].handlers[%d].type must be http", eventName, i, j)
				}
				if strings.TrimSpace(handler.URL) == "" {
					return fmt.Errorf("gateway_hooks.%s[%d].handlers[%d].url must be set", eventName, i, j)
				}
				if handler.TimeoutSeconds <= 0 {
					return fmt.Errorf("gateway_hooks.%s[%d].handlers[%d].timeout_seconds must be positive", eventName, i, j)
				}
				switch handler.FailureMode {
				case "", "fail_closed", "fail_open":
				default:
					return fmt.Errorf("gateway_hooks.%s[%d].handlers[%d].failure_mode must be fail_closed or fail_open", eventName, i, j)
				}
				if handler.SecretEnv != "" {
					if secret := strings.TrimSpace(os.Getenv(handler.SecretEnv)); secret == "" {
						return fmt.Errorf("gateway hook handler %q requires non-empty secret env %s", handler.Name, handler.SecretEnv)
					}
				}
			}
		}
	}
	return nil
}
```

Call it from `func (c *Config) Validate() error` before the final `return nil`:

```go
if err := c.GatewayHooks.Validate(); err != nil {
	return err
}
```

- [ ] **Step 6: Add gateway error codes**

In `pkg/gateway/errorcodes.go`, add:

```go
CodeHookFailed  = "HOOK_FAILED"
CodeHookBlocked = "HOOK_BLOCKED"
```

Place them in the execution group after `CodeAdapterError`.

- [ ] **Step 7: Run config tests**

Run:

```bash
go test ./pkg/config -run 'TestGatewayHooks|TestValidateGatewayHooks' -count=1
```

Expected: tests pass.

- [ ] **Step 8: Commit**

```bash
git add pkg/config/config.go pkg/config/config_test.go pkg/gateway/errorcodes.go
git commit -m "feat(gateway-hooks): add external hook config"
```

## Task 2: Add Hook Types And Matcher

**Files:**
- Create: `internal/gatewayhooks/types.go`
- Create: `internal/gatewayhooks/matcher.go`
- Create: `internal/gatewayhooks/matcher_test.go`

- [ ] **Step 1: Write matcher tests**

Create `internal/gatewayhooks/matcher_test.go`:

```go
package gatewayhooks

import (
	"testing"

	"github.com/clawvisor/clawvisor/pkg/config"
)

func TestMatchGatewayCall(t *testing.T) {
	tests := []struct {
		name    string
		matcher config.GatewayHookMatcherConfig
		service string
		action  string
		want    bool
	}{
		{
			name: "exact",
			matcher: config.GatewayHookMatcherConfig{Service: "google.gmail", Action: "get_message"},
			service: "google.gmail",
			action: "get_message",
			want: true,
		},
		{
			name: "alias normalized",
			matcher: config.GatewayHookMatcherConfig{Service: "google.gmail", Action: "get_message"},
			service: "google.gmail:personal",
			action: "get_message",
			want: true,
		},
		{
			name: "pipe list",
			matcher: config.GatewayHookMatcherConfig{Service: "google.gmail|google.drive", Action: "get_message|list_messages"},
			service: "google.gmail",
			action: "list_messages",
			want: true,
		},
		{
			name: "wildcard",
			matcher: config.GatewayHookMatcherConfig{Service: "*", Action: "*"},
			service: "slack",
			action: "list_messages",
			want: true,
		},
		{
			name: "service mismatch",
			matcher: config.GatewayHookMatcherConfig{Service: "google.drive", Action: "*"},
			service: "google.gmail",
			action: "get_message",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchGatewayCall(tt.matcher, tt.service, tt.action)
			if got != tt.want {
				t.Fatalf("MatchGatewayCall() = %v, want %v", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run matcher tests and confirm failure**

Run:

```bash
go test ./internal/gatewayhooks -run TestMatchGatewayCall -count=1
```

Expected: fail because the package does not exist.

- [ ] **Step 3: Add hook types**

Create `internal/gatewayhooks/types.go`:

```go
package gatewayhooks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/clawvisor/clawvisor/pkg/adapters"
)

const EventGatewayPostToolCall = "GatewayPostToolCall"

const (
	DecisionContinue = "continue"
	DecisionBlock    = "block"
)

const (
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
	FiltersApplied     json.RawMessage
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
```

- [ ] **Step 4: Add matcher implementation**

Create `internal/gatewayhooks/matcher.go`:

```go
package gatewayhooks

import (
	"strings"

	"github.com/clawvisor/clawvisor/pkg/config"
)

func MatchGatewayCall(m config.GatewayHookMatcherConfig, service, action string) bool {
	service = normalizeService(service)
	return matchTokenList(m.Service, service) && matchTokenList(m.Action, action)
}

func normalizeService(service string) string {
	service = strings.TrimSpace(service)
	if i := strings.Index(service, ":"); i >= 0 {
		return service[:i]
	}
	return service
}

func matchTokenList(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == "*" {
		return true
	}
	for _, part := range strings.Split(pattern, "|") {
		if strings.TrimSpace(part) == value {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run matcher tests**

Run:

```bash
go test ./internal/gatewayhooks -run TestMatchGatewayCall -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add internal/gatewayhooks/types.go internal/gatewayhooks/matcher.go internal/gatewayhooks/matcher_test.go
git commit -m "feat(gateway-hooks): add hook event types and matcher"
```

## Task 3: Add HTTP Hook Client With HMAC Signing

**Files:**
- Create: `internal/gatewayhooks/http_client.go`
- Create: `internal/gatewayhooks/http_client_test.go`

- [ ] **Step 1: Write HTTP client tests**

Create `internal/gatewayhooks/http_client_test.go`:

```go
package gatewayhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clawvisor/clawvisor/pkg/adapters"
	"github.com/clawvisor/clawvisor/pkg/config"
)

func TestHTTPHookClientSignsRequest(t *testing.T) {
	secret := "hook-secret"
	t.Setenv("CLAWVISOR_TEST_HOOK_SECRET", secret)
	var sawSignature bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readAllForTest(t, r)
		ts := r.Header.Get("X-Clawvisor-Hook-Timestamp")
		sig := r.Header.Get("X-Clawvisor-Hook-Signature")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if sig != want {
			t.Fatalf("signature = %q, want %q", sig, want)
		}
		if r.Header.Get("X-Clawvisor-Hook-Name") != "privacy-filter" {
			t.Fatalf("hook name header = %q", r.Header.Get("X-Clawvisor-Hook-Name"))
		}
		sawSignature = true
		_ = json.NewEncoder(w).Encode(HookResponse{
			HookEventName: EventGatewayPostToolCall,
			Decision: DecisionContinue,
			UpdatedToolResponse: &adapters.Result{Summary: "redacted"},
		})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.Client())
	client.now = func() time.Time { return time.Unix(1782500000, 0) }
	resp, _, err := client.Call(context.Background(), config.GatewayHookHandlerConfig{
		Name: "privacy-filter", Type: "http", URL: srv.URL, TimeoutSeconds: 5,
		AllowResponseUpdate: true, SecretEnv: "CLAWVISOR_TEST_HOOK_SECRET",
	}, HookRequest{
		HookEventName: EventGatewayPostToolCall,
		HookName: "privacy-filter",
		Service: "google.gmail",
		Action: "get_message",
		ToolName: "google.gmail.get_message",
		ToolResponse: &adapters.Result{Summary: "raw"},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !sawSignature {
		t.Fatal("test server did not observe signature")
	}
	if resp.UpdatedToolResponse == nil || resp.UpdatedToolResponse.Summary != "redacted" {
		t.Fatalf("updated response = %#v", resp.UpdatedToolResponse)
	}
}

func TestHTTPHookClientRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.Client())
	_, _, err := client.Call(context.Background(), config.GatewayHookHandlerConfig{
		Name: "bad-hook", Type: "http", URL: srv.URL, TimeoutSeconds: 5,
	}, HookRequest{HookEventName: EventGatewayPostToolCall, HookName: "bad-hook"})
	if err == nil {
		t.Fatal("expected non-2xx error")
	}
}

func TestHTTPHookClientRejectsInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not-json"))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.Client())
	_, _, err := client.Call(context.Background(), config.GatewayHookHandlerConfig{
		Name: "bad-json", Type: "http", URL: srv.URL, TimeoutSeconds: 5,
	}, HookRequest{HookEventName: EventGatewayPostToolCall, HookName: "bad-json"})
	if err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func readAllForTest(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body := make([]byte, r.ContentLength)
	if _, err := r.Body.Read(body); err != nil && err.Error() != "EOF" {
		t.Fatalf("read body: %v", err)
	}
	return body
}
```

- [ ] **Step 2: Run HTTP client tests and confirm failure**

Run:

```bash
go test ./internal/gatewayhooks -run 'TestHTTPHookClient' -count=1
```

Expected: compile failure because `NewHTTPClient` does not exist.

- [ ] **Step 3: Implement HTTP client**

Create `internal/gatewayhooks/http_client.go`:

```go
package gatewayhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/clawvisor/clawvisor/pkg/config"
)

const maxHookResponseBytes = 1 << 20

type HTTPClient struct {
	client *http.Client
	now    func() time.Time
}

func NewHTTPClient(client *http.Client) *HTTPClient {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPClient{client: client, now: time.Now}
}

func (c *HTTPClient) Call(ctx context.Context, cfg config.GatewayHookHandlerConfig, payload HookRequest) (HookResponse, HandlerSummary, error) {
	start := time.Now()
	summary := HandlerSummary{Name: cfg.Name, FailureMode: normalizedFailureMode(cfg.FailureMode)}
	body, err := json.Marshal(payload)
	if err != nil {
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Clawvisor-Hook-Name", cfg.Name)
	req.Header.Set("X-Clawvisor-Hook-Event", payload.HookEventName)
	if cfg.SecretEnv != "" {
		secret := strings.TrimSpace(os.Getenv(cfg.SecretEnv))
		if secret == "" {
			err := fmt.Errorf("hook secret env %s is empty", cfg.SecretEnv)
			summary.Error = err.Error()
			return HookResponse{}, summary, err
		}
		ts := fmt.Sprintf("%d", c.now().Unix())
		req.Header.Set("X-Clawvisor-Hook-Timestamp", ts)
		req.Header.Set("X-Clawvisor-Hook-Signature", signHookBody(secret, ts, body))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHookResponseBytes))
		err := fmt.Errorf("hook %q returned status %d", cfg.Name, resp.StatusCode)
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxHookResponseBytes+1))
	if err != nil {
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	if len(raw) > maxHookResponseBytes {
		err := fmt.Errorf("hook %q response exceeds %d bytes", cfg.Name, maxHookResponseBytes)
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	var out HookResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	summary.DurationMS = time.Since(start).Milliseconds()
	summary.Decision = out.Decision
	summary.UpdatedToolResponse = out.UpdatedToolResponse != nil
	summary.Metadata = out.AuditMetadata
	return out, summary, nil
}

func signHookBody(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func normalizedFailureMode(mode string) string {
	if mode == "fail_open" {
		return "fail_open"
	}
	return "fail_closed"
}
```

- [ ] **Step 4: Fix the test body reader**

Replace `readAllForTest` in `internal/gatewayhooks/http_client_test.go` with:

```go
func readAllForTest(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}
```

Add `io` to the test imports.

- [ ] **Step 5: Run HTTP client tests**

Run:

```bash
go test ./internal/gatewayhooks -run 'TestHTTPHookClient' -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add internal/gatewayhooks/http_client.go internal/gatewayhooks/http_client_test.go
git commit -m "feat(gateway-hooks): add signed HTTP hook client"
```

## Task 4: Add Gateway Hook Runner

**Files:**
- Create: `internal/gatewayhooks/runner.go`
- Create: `internal/gatewayhooks/runner_test.go`

- [ ] **Step 1: Write runner tests**

Create `internal/gatewayhooks/runner_test.go`:

```go
package gatewayhooks

import (
	"context"
	"encoding/json"
	"errors"
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
	summary := HandlerSummary{Name: cfg.Name, FailureMode: normalizedFailureMode(cfg.FailureMode)}
	if idx < len(f.errs) && f.errs[idx] != nil {
		summary.Error = f.errs[idx].Error()
		return HookResponse{}, summary, f.errs[idx]
	}
	resp := f.responses[idx]
	summary.Decision = resp.Decision
	summary.UpdatedToolResponse = resp.UpdatedToolResponse != nil
	summary.Metadata = resp.AuditMetadata
	return resp, summary, nil
}

func TestRunnerAppliesUpdatedToolResponse(t *testing.T) {
	caller := &fakeCaller{responses: []HookResponse{{
		HookEventName: EventGatewayPostToolCall,
		Decision: DecisionContinue,
		UpdatedToolResponse: &adapters.Result{Summary: "redacted"},
		AuditMetadata: map[string]any{"privacy_filter": map[string]any{"applied": true}},
	}}}
	runner := NewRunner(config.GatewayHooksConfig{
		Enabled: true,
		Events: map[string][]config.GatewayHookEventConfig{
			EventGatewayPostToolCall: {{
				Matcher: config.GatewayHookMatcherConfig{Service: "google.gmail", Action: "get_message"},
				Handlers: []config.GatewayHookHandlerConfig{{
					Name: "privacy-filter", Type: "http", URL: "http://hook", TimeoutSeconds: 10,
					FailureMode: "fail_closed", AllowResponseUpdate: true,
				}},
			}},
		},
	}, caller)
	out, err := runner.RunPostToolCall(context.Background(), PostToolCallEvent{
		RequestID: "req-1", AuditID: "audit-1", UserID: "user-1", AgentID: "agent-1",
		Service: "google.gmail", Action: "get_message", Reason: "fetch email",
		Params: map[string]any{"message_id": "m-1"},
		ToolResponse: &adapters.Result{Summary: "raw"},
	})
	if err != nil {
		t.Fatalf("RunPostToolCall: %v", err)
	}
	if out.ToolResponse.Summary != "redacted" {
		t.Fatalf("summary = %q, want redacted", out.ToolResponse.Summary)
	}
	if len(caller.seen) != 1 {
		t.Fatalf("hook calls = %d, want 1", len(caller.seen))
	}
	if !json.Valid(out.FiltersApplied) {
		t.Fatalf("filters_applied is not valid JSON: %s", out.FiltersApplied)
	}
}

func TestRunnerRejectsUnauthorizedMutation(t *testing.T) {
	caller := &fakeCaller{responses: []HookResponse{{
		HookEventName: EventGatewayPostToolCall,
		Decision: DecisionContinue,
		UpdatedToolResponse: &adapters.Result{Summary: "redacted"},
	}}}
	runner := NewRunner(config.GatewayHooksConfig{
		Enabled: true,
		Events: map[string][]config.GatewayHookEventConfig{
			EventGatewayPostToolCall: {{
				Matcher: config.GatewayHookMatcherConfig{Service: "*", Action: "*"},
				Handlers: []config.GatewayHookHandlerConfig{{
					Name: "observer", Type: "http", URL: "http://hook", TimeoutSeconds: 10, FailureMode: "fail_closed",
				}},
			}},
		},
	}, caller)
	_, err := runner.RunPostToolCall(context.Background(), PostToolCallEvent{
		Service: "google.gmail", Action: "get_message", ToolResponse: &adapters.Result{Summary: "raw"},
	})
	var hookErr *HookError
	if !errors.As(err, &hookErr) || hookErr.Code != ErrorCodeHookFailed {
		t.Fatalf("error = %v, want HOOK_FAILED", err)
	}
}

func TestRunnerFailOpenSkipsChainExtraction(t *testing.T) {
	caller := &fakeCaller{errs: []error{errors.New("offline")}}
	runner := NewRunner(config.GatewayHooksConfig{
		Enabled: true,
		Events: map[string][]config.GatewayHookEventConfig{
			EventGatewayPostToolCall: {{
				Matcher: config.GatewayHookMatcherConfig{Service: "*", Action: "*"},
				Handlers: []config.GatewayHookHandlerConfig{{
					Name: "optional", Type: "http", URL: "http://hook", TimeoutSeconds: 10, FailureMode: "fail_open",
				}},
			}},
		},
	}, caller)
	out, err := runner.RunPostToolCall(context.Background(), PostToolCallEvent{
		Service: "google.gmail", Action: "get_message", ToolResponse: &adapters.Result{Summary: "raw"},
	})
	if err != nil {
		t.Fatalf("fail_open returned error: %v", err)
	}
	if out.ToolResponse.Summary != "raw" {
		t.Fatalf("summary = %q, want raw", out.ToolResponse.Summary)
	}
	if !out.SkipChainExtraction {
		t.Fatal("fail_open hook failure must skip chain extraction")
	}
}

func TestRunnerBlockAlwaysBlocks(t *testing.T) {
	caller := &fakeCaller{responses: []HookResponse{{
		HookEventName: EventGatewayPostToolCall,
		Decision: DecisionBlock,
		AuditMetadata: map[string]any{"policy": map[string]any{"blocked": true}},
	}}}
	runner := NewRunner(config.GatewayHooksConfig{
		Enabled: true,
		Events: map[string][]config.GatewayHookEventConfig{
			EventGatewayPostToolCall: {{
				Matcher: config.GatewayHookMatcherConfig{Service: "*", Action: "*"},
				Handlers: []config.GatewayHookHandlerConfig{{
					Name: "blocker", Type: "http", URL: "http://hook", TimeoutSeconds: 10, FailureMode: "fail_open",
				}},
			}},
		},
	}, caller)
	_, err := runner.RunPostToolCall(context.Background(), PostToolCallEvent{
		Service: "google.gmail", Action: "get_message", ToolResponse: &adapters.Result{Summary: "raw"},
	})
	var hookErr *HookError
	if !errors.As(err, &hookErr) || hookErr.Code != ErrorCodeHookBlocked {
		t.Fatalf("error = %v, want HOOK_BLOCKED", err)
	}
}
```

- [ ] **Step 2: Run runner tests and confirm failure**

Run:

```bash
go test ./internal/gatewayhooks -run TestRunner -count=1
```

Expected: compile failure because `NewRunner` does not exist.

- [ ] **Step 3: Implement runner**

Create `internal/gatewayhooks/runner.go`:

```go
package gatewayhooks

import (
	"context"
	"encoding/json"
	"fmt"

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
	summaries := make([]HandlerSummary, 0)
	skipChain := false
	for _, entry := range entries {
		if !MatchGatewayCall(entry.Matcher, event.Service, event.Action) {
			continue
		}
		for _, handler := range entry.Handlers {
			req := HookRequest{
				HookEventName: EventGatewayPostToolCall,
				HookName: handler.Name,
				RequestID: event.RequestID,
				AuditID: event.AuditID,
				UserID: event.UserID,
				AgentID: event.AgentID,
				TaskID: event.TaskID,
				SessionID: event.SessionID,
				Service: normalizeService(event.Service),
				Action: event.Action,
				ToolName: normalizeService(event.Service) + "." + event.Action,
				ToolInput: ToolInput{Params: event.Params, Reason: event.Reason},
				ToolResponse: current,
			}
			resp, summary, err := r.caller.Call(ctx, handler, req)
			if err != nil {
				summaries = append(summaries, summary)
				filters := marshalFiltersApplied(summaries)
				if normalizedFailureMode(handler.FailureMode) == "fail_open" {
					return &RunResult{ToolResponse: current, FiltersApplied: filters, SkipChainExtraction: true}, nil
				}
				return nil, &HookError{Code: ErrorCodeHookFailed, Message: err.Error(), FiltersApplied: filters, SkipChainExtraction: true}
			}
			protocolErr := validateHookResponse(handler, resp)
			if protocolErr != nil {
				summary.Error = protocolErr.Error()
				summaries = append(summaries, summary)
				filters := marshalFiltersApplied(summaries)
				if normalizedFailureMode(handler.FailureMode) == "fail_open" {
					return &RunResult{ToolResponse: current, FiltersApplied: filters, SkipChainExtraction: true}, nil
				}
				return nil, &HookError{Code: ErrorCodeHookFailed, Message: protocolErr.Error(), FiltersApplied: filters, SkipChainExtraction: true}
			}
			summaries = append(summaries, summary)
			if resp.Decision == DecisionBlock {
				filters := marshalFiltersApplied(summaries)
				return nil, &HookError{Code: ErrorCodeHookBlocked, Message: "gateway hook blocked the tool response", FiltersApplied: filters, SkipChainExtraction: true}
			}
			if resp.UpdatedToolResponse != nil {
				current = resp.UpdatedToolResponse
			}
			if len(summaries) > 0 {
				skipChain = false
			}
		}
	}
	return &RunResult{ToolResponse: current, FiltersApplied: marshalFiltersApplied(summaries), SkipChainExtraction: skipChain}, nil
}

func validateHookResponse(handler config.GatewayHookHandlerConfig, resp HookResponse) error {
	if resp.HookEventName != EventGatewayPostToolCall {
		return fmt.Errorf("hook %q returned event %q", handler.Name, resp.HookEventName)
	}
	switch resp.Decision {
	case DecisionContinue, DecisionBlock:
	default:
		return fmt.Errorf("hook %q returned unsupported decision %q", handler.Name, resp.Decision)
	}
	if resp.UpdatedToolResponse != nil && !handler.AllowResponseUpdate {
		return fmt.Errorf("hook %q returned updated_tool_response without allow_response_update", handler.Name)
	}
	return nil
}

func marshalFiltersApplied(summaries []HandlerSummary) json.RawMessage {
	if len(summaries) == 0 {
		return nil
	}
	payload := map[string]any{
		"gateway_hooks": map[string]any{
			EventGatewayPostToolCall: summaries,
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return raw
}
```

- [ ] **Step 4: Run runner tests**

Run:

```bash
go test ./internal/gatewayhooks -run TestRunner -count=1
```

Expected: pass.

- [ ] **Step 5: Run all gatewayhooks tests**

Run:

```bash
go test ./internal/gatewayhooks -count=1
```

Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add internal/gatewayhooks/runner.go internal/gatewayhooks/runner_test.go
git commit -m "feat(gateway-hooks): add post tool call runner"
```

## Task 5: Persist Hook Metadata In Audit Rows

**Files:**
- Modify: `pkg/store/store.go`
- Modify: `pkg/store/sqlite/store.go`
- Modify: `pkg/store/postgres/store.go`
- Modify: `pkg/store/sqlite/sqlite_test.go`
- Modify: `internal/api/handlers/local_service_test.go`

- [ ] **Step 1: Write SQLite audit filter update test**

Append this test to `pkg/store/sqlite/sqlite_test.go`:

```go
func TestUpdateAuditFiltersApplied(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.New(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	st := sqlite.NewStore(db)
	t.Cleanup(func() { _ = st.Close() })

	entry := &store.AuditEntry{
		ID: "audit-filter-1", UserID: "user-1", RequestID: "req-1",
		Timestamp: time.Now(), Service: "google.gmail", Action: "get_message",
		ParamsSafe: json.RawMessage(`{}`), Decision: "execute", Outcome: "pending",
	}
	if err := st.LogAudit(ctx, entry); err != nil {
		t.Fatalf("LogAudit: %v", err)
	}
	filters := json.RawMessage(`{"gateway_hooks":{"GatewayPostToolCall":[{"name":"privacy-filter"}]}}`)
	if err := st.UpdateAuditFiltersApplied(ctx, entry.ID, filters); err != nil {
		t.Fatalf("UpdateAuditFiltersApplied: %v", err)
	}
	got, err := st.GetAuditEntry(ctx, entry.ID, entry.UserID)
	if err != nil {
		t.Fatalf("GetAuditEntry: %v", err)
	}
	if string(got.FiltersApplied) != string(filters) {
		t.Fatalf("FiltersApplied = %s, want %s", got.FiltersApplied, filters)
	}
}
```

Add missing imports to `pkg/store/sqlite/sqlite_test.go`:

```go
import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/clawvisor/clawvisor/pkg/store"
)
```

Merge with the existing import block.

- [ ] **Step 2: Run SQLite test and confirm failure**

Run:

```bash
go test ./pkg/store/sqlite -run TestUpdateAuditFiltersApplied -count=1
```

Expected: compile failure because `UpdateAuditFiltersApplied` does not exist.

- [ ] **Step 3: Add store interface method**

In `pkg/store/store.go`, add this method after `UpdateAuditOutcome`:

```go
UpdateAuditFiltersApplied(ctx context.Context, id string, filters json.RawMessage) error
```

- [ ] **Step 4: Implement SQLite method**

In `pkg/store/sqlite/store.go`, add after `UpdateAuditOutcome`:

```go
func (s *Store) UpdateAuditFiltersApplied(ctx context.Context, id string, filters json.RawMessage) error {
	var value *string
	if len(filters) > 0 {
		str := string(filters)
		value = &str
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE audit_log SET filters_applied = ? WHERE id = ?`,
		value, id)
	return err
}
```

- [ ] **Step 5: Implement Postgres method**

In `pkg/store/postgres/store.go`, add after `UpdateAuditOutcome`:

```go
func (s *Store) UpdateAuditFiltersApplied(ctx context.Context, id string, filters json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE audit_log SET filters_applied = $1 WHERE id = $2`,
		nilIfEmpty(filters), id)
	return err
}
```

- [ ] **Step 6: Update handler test store**

In `internal/api/handlers/local_service_test.go`, add this method after `UpdateAuditOutcome`:

```go
func (s *localTestStore) UpdateAuditFiltersApplied(_ context.Context, id string, filters json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.auditEntries {
		if e.ID == id {
			e.FiltersApplied = append(json.RawMessage(nil), filters...)
			return nil
		}
	}
	return nil
}
```

- [ ] **Step 7: Run store tests**

Run:

```bash
go test ./pkg/store/sqlite -run TestUpdateAuditFiltersApplied -count=1
```

Expected: pass.

- [ ] **Step 8: Run compile checks for affected packages**

Run:

```bash
go test ./pkg/store/... ./internal/api/handlers -run 'TestUpdateAuditFiltersApplied|TestNonExistent' -count=1
```

Expected: packages compile; the `TestNonExistent` filter runs no handler tests.

- [ ] **Step 9: Commit**

```bash
git add pkg/store/store.go pkg/store/sqlite/store.go pkg/store/postgres/store.go pkg/store/sqlite/sqlite_test.go internal/api/handlers/local_service_test.go
git commit -m "feat(gateway-hooks): persist hook audit metadata"
```

## Task 6: Wire Hook Runner Into Server And Gateway Handlers

**Files:**
- Modify: `internal/api/server.go`
- Modify: `internal/api/handlers/gateway.go`
- Modify: `internal/api/handlers/approvals.go`
- Modify: `internal/api/handlers/services.go`

- [ ] **Step 1: Add handler runner fields and setters**

In `internal/api/handlers/gateway.go`, import `github.com/clawvisor/clawvisor/internal/gatewayhooks`.

Add this field to `GatewayHandler`:

```go
postToolCallHooks gatewayhooks.PostToolCallRunner
```

Add this setter after `SetGatewayHooks`:

```go
func (h *GatewayHandler) SetPostToolCallHookRunner(r gatewayhooks.PostToolCallRunner) {
	h.postToolCallHooks = r
}
```

In `internal/api/handlers/approvals.go`, import `github.com/clawvisor/clawvisor/internal/gatewayhooks`, add this field to `ApprovalsHandler`:

```go
postToolCallHooks gatewayhooks.PostToolCallRunner
```

Add this setter after `SetCallbackDispatcher`:

```go
func (h *ApprovalsHandler) SetPostToolCallHookRunner(r gatewayhooks.PostToolCallRunner) {
	h.postToolCallHooks = r
}
```

In `internal/api/handlers/services.go`, import `github.com/clawvisor/clawvisor/internal/gatewayhooks`, add this field to `ServicesHandler`:

```go
postToolCallHooks gatewayhooks.PostToolCallRunner
```

Add this setter near the existing service handler setters:

```go
func (h *ServicesHandler) SetPostToolCallHookRunner(r gatewayhooks.PostToolCallRunner) {
	h.postToolCallHooks = r
}
```

- [ ] **Step 2: Add shared hook helper**

In `internal/api/handlers/gateway.go`, add:

```go
type postToolCallHookInput struct {
	RequestID string
	AuditID   string
	UserID    string
	AgentID   string
	TaskID    string
	SessionID string
	Service   string
	Action    string
	Params    map[string]any
	Reason    string
}

func applyPostToolCallHooks(
	ctx context.Context,
	runner gatewayhooks.PostToolCallRunner,
	st store.Store,
	in postToolCallHookInput,
	result *adapters.Result,
) (*adapters.Result, bool, error) {
	if runner == nil || result == nil {
		return result, false, nil
	}
	out, err := runner.RunPostToolCall(ctx, gatewayhooks.PostToolCallEvent{
		RequestID: in.RequestID,
		AuditID: in.AuditID,
		UserID: in.UserID,
		AgentID: in.AgentID,
		TaskID: in.TaskID,
		SessionID: in.SessionID,
		Service: in.Service,
		Action: in.Action,
		Params: in.Params,
		Reason: in.Reason,
		ToolResponse: result,
	})
	if err != nil {
		var hookErr *gatewayhooks.HookError
		if errors.As(err, &hookErr) && len(hookErr.FiltersApplied) > 0 {
			_ = st.UpdateAuditFiltersApplied(context.WithoutCancel(ctx), in.AuditID, hookErr.FiltersApplied)
			return result, hookErr.SkipChainExtraction, err
		}
		return result, true, err
	}
	if out == nil {
		return result, false, nil
	}
	if len(out.FiltersApplied) > 0 {
		_ = st.UpdateAuditFiltersApplied(context.WithoutCancel(ctx), in.AuditID, out.FiltersApplied)
	}
	if out.ToolResponse != nil {
		result = out.ToolResponse
	}
	return result, out.SkipChainExtraction, nil
}

func hookGatewayErrorCode(err error) string {
	var hookErr *gatewayhooks.HookError
	if errors.As(err, &hookErr) && hookErr.Code == gatewayhooks.ErrorCodeHookBlocked {
		return gateway.CodeHookBlocked
	}
	return gateway.CodeHookFailed
}
```

This code uses `errors`, `adapters`, `store`, `gateway`, and `gatewayhooks`; ensure imports are present.

- [ ] **Step 3: Construct runner in server**

In `internal/api/server.go`, import:

```go
"github.com/clawvisor/clawvisor/internal/gatewayhooks"
```

Add this field to `Server`:

```go
gatewayPostToolCallHooks gatewayhooks.PostToolCallRunner
```

In `api.New`, after logger setup and before `mux := s.routes()`, add:

```go
if cfg.GatewayHooks.Enabled {
	s.gatewayPostToolCallHooks = gatewayhooks.NewRunner(cfg.GatewayHooks, nil)
}
```

In `routes`, after each handler is constructed, wire the runner:

```go
if s.gatewayPostToolCallHooks != nil {
	gatewayHandler.SetPostToolCallHookRunner(s.gatewayPostToolCallHooks)
}
```

After `servicesHandler := handlers.NewServicesHandler(...)`, add:

```go
if s.gatewayPostToolCallHooks != nil {
	servicesHandler.SetPostToolCallHookRunner(s.gatewayPostToolCallHooks)
}
```

After `approvalsHandler.SetCallbackDispatcher(s.cbDispatcher)`, add:

```go
if s.gatewayPostToolCallHooks != nil {
	approvalsHandler.SetPostToolCallHookRunner(s.gatewayPostToolCallHooks)
}
```

- [ ] **Step 4: Wire auto-execute path**

In `internal/api/handlers/gateway.go`, in the auto-execute success path after `execErr` is confirmed nil and before `UpdateAuditOutcome(..., "executed", ...)`, add:

```go
skipChainExtraction := false
result, skipChainExtraction, execErr = applyPostToolCallHooks(ctx, h.postToolCallHooks, h.store, postToolCallHookInput{
	RequestID: req.RequestID,
	AuditID: auditID,
	UserID: agent.UserID,
	AgentID: agent.ID,
	TaskID: req.TaskID,
	SessionID: req.SessionID,
	Service: req.Service,
	Action: req.Action,
	Params: req.Params,
	Reason: req.Reason,
}, result)
if execErr != nil {
	errMsg := execErr.Error()
	if updErr := h.store.UpdateAuditOutcome(finalizeCtx, auditID, "error", errMsg, dur); updErr != nil {
		h.logger.WarnContext(ctx, "audit outcome update failed", "err", updErr)
	}
	outDecision, outOutcome = "execute", "error"
	h.publishAuditAndQueue(agent.UserID, req.TaskID)
	if req.Context.CallbackURL != "" {
		cbKey, _ := h.store.GetAgentCallbackSecret(finalizeCtx, agent.ID)
		h.dispatchCallback(req.Context.CallbackURL, &callback.Payload{
			Type: "request", RequestID: req.RequestID, Status: "error", Error: errMsg, AuditID: auditID,
		}, cbKey)
	}
	resp := map[string]any{
		"status": "error", "request_id": req.RequestID, "audit_id": auditID,
		"error": errMsg, "code": hookGatewayErrorCode(execErr),
	}
	h.maybeInjectNPS(ctx, resp, agent.ID)
	writeJSON(w, http.StatusOK, resp)
	return
}
```

Then guard chain extraction:

```go
if !skipChainExtraction {
	h.startChainExtraction(task, req.Service, req.Action, result,
		req.TaskID, req.SessionID, auditID, runLLM)
}
```

- [ ] **Step 5: Wire approved synchronous execution**

In `executeAndRespond`, after adapter execution and before computing final response success body, call:

```go
skipChainExtraction := false
if execErr == nil {
	result, skipChainExtraction, execErr = applyPostToolCallHooks(ctx, h.postToolCallHooks, h.store, postToolCallHookInput{
		RequestID: pa.RequestID,
		AuditID: pa.AuditID,
		UserID: pa.UserID,
		AgentID: agentID,
		TaskID: blob.TaskID,
		SessionID: blob.SessionID,
		Service: blob.Service,
		Action: blob.Action,
		Params: blob.Params,
		Reason: blob.Reason,
	}, result)
}
```

Use `hookGatewayErrorCode(execErr)` when populating `resp["code"]` for hook errors. Guard `h.startChainExtraction` with `!skipChainExtraction`.

- [ ] **Step 6: Wire async approval callback execution**

In `ApprovalsHandler.executeApproval`, after `executeAdapterRequest` returns and before `outcome := "executed"`, add:

```go
if execErr == nil {
	result, _, execErr = applyPostToolCallHooks(ctx, h.postToolCallHooks, h.st, postToolCallHookInput{
		RequestID: pa.RequestID,
		AuditID: pa.AuditID,
		UserID: pa.UserID,
		AgentID: blob.AgentID,
		TaskID: blob.TaskID,
		SessionID: blob.SessionID,
		Service: blob.Service,
		Action: blob.Action,
		Params: blob.Params,
		Reason: blob.Reason,
	}, result)
}
```

This path does not start chain extraction today, so no chain extraction guard is needed here.

- [ ] **Step 7: Wire pending activation re-execution**

In `ServicesHandler.reactivatePendingRequest`, after `executeAdapterRequest` returns and before `outcome := "executed"`, add:

```go
if execErr == nil {
	result, _, execErr = applyPostToolCallHooks(ctx, h.postToolCallHooks, h.st, postToolCallHookInput{
		RequestID: requestID,
		AuditID: pa.AuditID,
		UserID: userID,
		AgentID: blob.AgentID,
		TaskID: blob.TaskID,
		SessionID: blob.SessionID,
		Service: blob.Service,
		Action: blob.Action,
		Params: blob.Params,
		Reason: blob.Reason,
	}, result)
}
```

- [ ] **Step 8: Compile affected packages**

Run:

```bash
go test ./internal/api ./internal/api/handlers -run 'TestNonExistent' -count=1
```

Expected: packages compile.

- [ ] **Step 9: Commit**

```bash
git add internal/api/server.go internal/api/handlers/gateway.go internal/api/handlers/approvals.go internal/api/handlers/services.go
git commit -m "feat(gateway-hooks): run post tool call hooks before egress"
```

## Task 7: Add API Integration Tests

**Files:**
- Add: `internal/api/gateway_external_hooks_test.go`
- Modify: `internal/api/handlers/chain_extraction_wiring_test.go`
- Add: `internal/api/handlers/gateway_external_hooks_chain_test.go`

- [ ] **Step 1: Write API test helper**

Create `internal/api/gateway_external_hooks_test.go` with the package and helper:

```go
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
```

- [ ] **Step 2: Add redacted HTTP response test**

Append to `internal/api/gateway_external_hooks_test.go`:

```go
func TestGatewayExternalHook_RedactsAutoExecuteResponse(t *testing.T) {
	secret := "hook-secret"
	t.Setenv("CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET", secret)
	hookSrv, seen := newGatewayHookServer(t, secret, map[string]any{
		"hook_event_name": "GatewayPostToolCall",
		"decision": "continue",
		"updated_tool_response": map[string]any{
			"summary": "Email from [PRIVATE_PERSON]",
			"data": map[string]any{"body": "hello [PRIVATE_PERSON]"},
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

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
```

Add `strings` to imports.

- [ ] **Step 3: Add callback redaction test**

Append:

```go
func TestGatewayExternalHook_RedactsCallbackPayload(t *testing.T) {
	t.Setenv("CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET", "hook-secret")
	hookSrv, _ := newGatewayHookServer(t, "hook-secret", map[string]any{
		"hook_event_name": "GatewayPostToolCall",
		"decision": "continue",
		"updated_tool_response": map[string]any{
			"summary": "Callback [PRIVATE_PERSON]",
			"data": map[string]any{"body": "[PRIVATE_PERSON]"},
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
		if !strings.Contains(payload, "[PRIVATE_PERSON]") {
			t.Fatalf("redacted callback missing marker: %s", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("callback not received")
	}
}
```

- [ ] **Step 4: Add fail-closed test**

Append:

```go
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
```

- [ ] **Step 5: Run API external hook tests and confirm compile failures**

Run:

```bash
go test ./internal/api -run 'TestGatewayExternalHook' -count=1
```

Expected before Task 6 is implemented: compile failures or test failures. After Task 6, expected: pass.

- [ ] **Step 6: Extend recording extractor to capture the extraction input**

In `internal/api/handlers/chain_extraction_wiring_test.go`, add this field to `recordingExtractor`:

```go
lastBuiltinResult string
```

In `ExtractBuiltins`, set it while holding the lock:

```go
r.lastBuiltinResult = req.Result
```

Add this helper after `llmCallCount`:

```go
func (r *recordingExtractor) lastBuiltinResultValue() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastBuiltinResult
}
```

- [ ] **Step 7: Add handler-level chain extraction test**

Create `internal/api/handlers/gateway_external_hooks_chain_test.go`:

```go
package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/clawvisor/clawvisor/internal/gatewayhooks"
	"github.com/clawvisor/clawvisor/internal/intent"
	"github.com/clawvisor/clawvisor/pkg/adapters"
	"github.com/clawvisor/clawvisor/pkg/store"
)

type redactingPostToolCallRunner struct{}

func (redactingPostToolCallRunner) RunPostToolCall(_ context.Context, event gatewayhooks.PostToolCallEvent) (*gatewayhooks.RunResult, error) {
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
	if !strings.Contains(resultSeenByExtractor, "redacted summary") {
		t.Fatalf("chain extraction saw %q, want redacted summary", resultSeenByExtractor)
	}
	if strings.Contains(resultSeenByExtractor, "raw summary") {
		t.Fatalf("chain extraction saw raw result: %q", resultSeenByExtractor)
	}
}
```

- [ ] **Step 8: Run integration tests**

Run:

```bash
go test ./internal/api ./internal/api/handlers -run 'TestGatewayExternalHook' -count=1
```

Expected: pass.

- [ ] **Step 9: Commit**

```bash
git add internal/api/gateway_external_hooks_test.go internal/api/handlers/chain_extraction_wiring_test.go internal/api/handlers/gateway_external_hooks_chain_test.go
git commit -m "test(gateway-hooks): cover external hook egress paths"
```

## Task 8: Add Hook Documentation

**Files:**
- Add: `docs/GATEWAY_HOOKS.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `AGENTS.md`

- [ ] **Step 1: Add operator docs**

Create `docs/GATEWAY_HOOKS.md` with:

```markdown
# Gateway Hooks

Gateway hooks are external HTTP handlers that Clawvisor can call during native
gateway execution. V1 supports one event: `GatewayPostToolCall`.

`GatewayPostToolCall` fires after an adapter succeeds and before the result is
returned to HTTP clients, callbacks, or chain-context extraction.

## Example

```yaml
gateway_hooks:
  enabled: true
  events:
    GatewayPostToolCall:
      - matcher:
          service: "google.gmail"
          action: "get_message|list_messages"
        handlers:
          - name: "privacy-filter"
            type: "http"
            url: "http://127.0.0.1:8765/v1/hooks/gateway/post-tool-call"
            timeout_seconds: 10
            failure_mode: "fail_closed"
            allow_response_update: true
            secret_env: "CLAWVISOR_PRIVACY_FILTER_HOOK_SECRET"
```

## Security

Hook services receive adapter results for matched calls. Treat them as trusted
services. Bind hook services to localhost or a private network. When
`secret_env` is set, Clawvisor signs each request with HMAC-SHA256 using
`X-Clawvisor-Hook-Signature`.

Gateway hooks are not a compliance guarantee. A privacy-filter hook is a data
minimization mitigation.

## Failure Modes

`fail_closed` prevents raw result egress on timeout, non-2xx response, invalid
JSON, schema mismatch, unauthorized mutation, or hook transport failure.

`fail_open` records failure metadata and returns the current result, but skips
chain-context extraction for that result.
```
```

- [ ] **Step 2: Update architecture docs**

In `docs/ARCHITECTURE.md`, update the execution path section so adapter execution is followed by:

```markdown
4. **Gateway Post-Tool-Call Hooks** (optional): If `gateway_hooks` are enabled,
   Clawvisor sends the adapter result to matching external HTTP hooks. Hooks may
   return an updated result. The hook-updated result is the only result used for
   HTTP responses, callbacks, and chain-context extraction. Hook metadata is
   stored in `audit_log.filters_applied`.
```

Renumber the following steps in that subsection.

- [ ] **Step 3: Update AGENTS.md**

In `AGENTS.md`, add gateway hooks to the high-risk areas:

```markdown
Gateway hook behavior is security-sensitive because hooks can see and mutate
adapter results before they reach agents, callbacks, or chain-context
extraction. Do not log raw hook payloads, hook responses, credentials, tokens,
or full downstream bodies.
```

- [ ] **Step 4: Run docs checks**

Run:

```bash
rg -n "gateway_hooks|GatewayPostToolCall|HOOK_FAILED|HOOK_BLOCKED" docs/GATEWAY_HOOKS.md docs/ARCHITECTURE.md AGENTS.md
```

Expected: matches in all three files.

- [ ] **Step 5: Commit**

```bash
git add docs/GATEWAY_HOOKS.md docs/ARCHITECTURE.md AGENTS.md
git commit -m "docs(gateway-hooks): document external hook protocol"
```

## Task 9: Final Verification

**Files:**
- No code changes unless verification finds a defect.

- [ ] **Step 1: Run focused tests**

Run:

```bash
go test ./pkg/config ./internal/gatewayhooks ./pkg/store/sqlite ./internal/api ./internal/api/handlers -count=1
```

Expected: all listed packages pass.

- [ ] **Step 2: Run full backend tests**

Run:

```bash
go test ./...
```

Expected: all packages pass or known baseline failures are unchanged from Task 0.

- [ ] **Step 3: Run lint**

Run:

```bash
go vet ./...
```

Expected: no new vet failures.

- [ ] **Step 4: Inspect worktree**

Run:

```bash
git status --short
```

Expected: clean worktree after all commits.

- [ ] **Step 5: Record verification**

In the final implementation response, include exact commands run and whether they passed. If any command cannot run because Go is unavailable, state that explicitly and include the last failing shell output.

## Spec Coverage Self-Review

- Generic external HTTP hook API: Tasks 1, 2, 3, and 4.
- `GatewayPostToolCall` event: Tasks 2, 4, and 6.
- Service/action matchers: Tasks 1, 2, and 4.
- HMAC auth via `secret_env`: Tasks 1 and 3.
- Result mutation before egress: Tasks 4, 6, and 7.
- Fail-open/fail-closed/block behavior: Tasks 4, 6, and 7.
- Audit metadata in `filters_applied`: Tasks 4, 5, and 7.
- Response, callback, and chain extraction coverage: Tasks 6 and 7.
- No OpenAI Privacy Filter dependency in core: preserved by package design and docs in Tasks 1 through 8.
