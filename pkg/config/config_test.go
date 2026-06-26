package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAppliesRuntimeProxyTimingTraceEnv(t *testing.T) {
	t.Setenv("CLAWVISOR_RUNTIME_PROXY_TIMING_TRACE_ENABLED", "true")
	t.Setenv("CLAWVISOR_RUNTIME_PROXY_TIMING_TRACE_DIR", "/tmp/clawvisor-timing-traces")
	t.Setenv("CLAWVISOR_RUNTIME_PROXY_BODY_TRACE_ENABLED", "true")
	t.Setenv("CLAWVISOR_RUNTIME_PROXY_BODY_TRACE_DIR", "/tmp/clawvisor-body-traces")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.RuntimeProxy.TimingTraceEnabled {
		t.Fatal("expected timing trace env override to enable runtime proxy timing traces")
	}
	if cfg.RuntimeProxy.TimingTraceDir != "/tmp/clawvisor-timing-traces" {
		t.Fatalf("expected timing trace dir override, got %q", cfg.RuntimeProxy.TimingTraceDir)
	}
	if !cfg.RuntimeProxy.BodyTraceEnabled {
		t.Fatal("expected body trace env override to enable runtime proxy body traces")
	}
	if cfg.RuntimeProxy.BodyTraceDir != "/tmp/clawvisor-body-traces" {
		t.Fatalf("expected body trace dir override, got %q", cfg.RuntimeProxy.BodyTraceDir)
	}
}

func TestLoadAppliesProxyLiteCloudEnv(t *testing.T) {
	t.Setenv("CLAWVISOR_ROUTE_SET", "proxy_lite")
	t.Setenv("CLAWVISOR_PROXY_LITE_ENABLED", "true")
	t.Setenv("CLAWVISOR_PROXY_LITE_PUBLIC_URL", "https://llm.example.com/")
	t.Setenv("CLAWVISOR_PROXY_LITE_ANTHROPIC_BASE_URL", "https://anthropic.internal")
	t.Setenv("CLAWVISOR_PROXY_LITE_OPENAI_BASE_URL", "https://openai.internal")
	t.Setenv("CLAWVISOR_PROXY_LITE_SELF_HOSTNAMES", "app.example.com, llm.example.com")
	t.Setenv("CLAWVISOR_PROXY_LITE_ALLOW_PRIVATE_NETWORKS", "false")
	t.Setenv("CLAWVISOR_PROXY_LITE_TRACE_LOG_PATH", "/tmp/lite-trace.jsonl")
	t.Setenv("CLAWVISOR_PROXY_LITE_RAW_LOG_PATH", "/tmp/lite-raw.jsonl")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.RouteSet != "proxy_lite" {
		t.Fatalf("RouteSet=%q, want proxy_lite", cfg.Server.RouteSet)
	}
	if !cfg.ProxyLite.Enabled {
		t.Fatal("expected proxy lite enabled")
	}
	if cfg.ProxyLite.PublicURL != "https://llm.example.com" {
		t.Fatalf("PublicURL=%q", cfg.ProxyLite.PublicURL)
	}
	if cfg.ProxyLite.AnthropicBaseURL != "https://anthropic.internal" {
		t.Fatalf("AnthropicBaseURL=%q", cfg.ProxyLite.AnthropicBaseURL)
	}
	if cfg.ProxyLite.OpenAIBaseURL != "https://openai.internal" {
		t.Fatalf("OpenAIBaseURL=%q", cfg.ProxyLite.OpenAIBaseURL)
	}
	if got := strings.Join(cfg.ProxyLite.SelfHostnames, ","); got != "app.example.com,llm.example.com" {
		t.Fatalf("SelfHostnames=%q", got)
	}
	if cfg.ProxyLite.AllowPrivateNetworks {
		t.Fatal("expected private networks disabled")
	}
	if cfg.ProxyLite.TraceLogPath != "/tmp/lite-trace.jsonl" {
		t.Fatalf("TraceLogPath=%q", cfg.ProxyLite.TraceLogPath)
	}
	if cfg.ProxyLite.RawLogPath != "/tmp/lite-raw.jsonl" {
		t.Fatalf("RawLogPath=%q", cfg.ProxyLite.RawLogPath)
	}
}

func TestValidateProxyLiteRouteSetRequiresProxyLite(t *testing.T) {
	cfg := Default()
	cfg.Server.RouteSet = "proxy_lite"
	cfg.ProxyLite.Enabled = false

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "proxy_lite.enabled") {
		t.Fatalf("expected proxy_lite.enabled validation error, got %v", err)
	}
}

func TestValidateRequiresTimingTraceDirWhenEnabled(t *testing.T) {
	cfg := Default()
	cfg.RuntimeProxy.TimingTraceEnabled = true
	cfg.RuntimeProxy.TimingTraceDir = "   "

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "runtime_proxy.timing_trace_dir") {
		t.Fatalf("expected timing trace dir validation error, got %v", err)
	}
}

func TestValidateRequiresBodyTraceDirWhenEnabled(t *testing.T) {
	cfg := Default()
	cfg.RuntimeProxy.BodyTraceEnabled = true
	cfg.RuntimeProxy.BodyTraceDir = "   "

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "runtime_proxy.body_trace_dir") {
		t.Fatalf("expected body trace dir validation error, got %v", err)
	}
}

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

func TestGatewayHooksWhitespaceEnvJSONIgnored(t *testing.T) {
	t.Setenv("CLAWVISOR_GATEWAY_HOOKS_JSON", " \n\t ")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GatewayHooks.Enabled {
		t.Fatal("gateway hooks should remain disabled for whitespace-only env JSON")
	}
	if len(cfg.GatewayHooks.Events) != 0 {
		t.Fatalf("gateway hook events = %#v, want default empty", cfg.GatewayHooks.Events)
	}
}

func TestGatewayHooksEnvJSONReplacesFileConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
gateway_hooks:
  enabled: true
  events:
    GatewayPostToolCall:
      - matcher:
          service: google.drive
          action: list_files
        handlers:
          - name: drive-filter
            type: http
            url: http://127.0.0.1:8765/hook
            timeout_seconds: 5
            failure_mode: fail_closed
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CLAWVISOR_GATEWAY_HOOKS_JSON", `{"enabled":true,"events":{}}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.GatewayHooks.Enabled {
		t.Fatal("expected gateway hooks enabled from env JSON")
	}
	if len(cfg.GatewayHooks.Events) != 0 {
		t.Fatalf("gateway hook events = %#v, want env JSON replacement with zero events", cfg.GatewayHooks.Events)
	}
}

func TestValidateGatewayHooksIgnoresMalformedEventsWhenDisabled(t *testing.T) {
	cfg := Default()
	cfg.GatewayHooks = GatewayHooksConfig{
		Enabled: false,
		Events: map[string][]GatewayHookEventConfig{
			"UnsupportedEvent": {{
				Matcher: GatewayHookMatcherConfig{},
				Handlers: []GatewayHookHandlerConfig{{
					Type:           "not-http",
					TimeoutSeconds: -1,
					FailureMode:    "explode",
				}},
			}},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateGatewayHooksAllowsZeroTimeout(t *testing.T) {
	cfg := Default()
	cfg.GatewayHooks = GatewayHooksConfig{
		Enabled: true,
		Events: map[string][]GatewayHookEventConfig{
			"GatewayPostToolCall": {{
				Matcher: GatewayHookMatcherConfig{Service: "google.gmail", Action: "get_message"},
				Handlers: []GatewayHookHandlerConfig{{
					Name: "privacy-filter",
					Type: "http",
					URL:  "http://127.0.0.1:8765/hook",
				}},
			}},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateGatewayHooksRejectsNegativeTimeout(t *testing.T) {
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
					TimeoutSeconds: -1,
				}},
			}},
		},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "timeout_seconds must be non-negative") {
		t.Fatalf("expected negative timeout validation error, got %v", err)
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

// TestInheritLLMDefaults_DoesNotInheritAnthropicEndpointIntoNonAnthropicSubBlock
// covers two cases where the Anthropic-default endpoint must NOT propagate
// into a sub-block that runs on a different provider:
//
//  1. Top-level switches to gemini (sub-block inherits provider).
//  2. Mixed providers: top-level stays anthropic, sub-block overrides to gemini.
//
// In both cases the sub-block's Endpoint must end up empty so the
// per-provider URL builder in llm.NewClient kicks in. Without this, gemini
// requests POST to api.anthropic.com and Cloudflare 404s.
func TestInheritLLMDefaults_DoesNotInheritAnthropicEndpointIntoNonAnthropicSubBlock(t *testing.T) {
	const anthropicURL = "https://api.anthropic.com/v1"

	// Case 1: top-level provider=gemini, sub-blocks inherit.
	t.Run("top_level_gemini", func(t *testing.T) {
		shared := &LLMConfig{Provider: "gemini", Endpoint: anthropicURL}
		sub := &LLMProviderConfig{}
		inheritLLMDefaults(sub, shared)
		if sub.Endpoint != "" {
			t.Errorf("sub Endpoint: got %q, want empty (so URL builder fires)", sub.Endpoint)
		}
		if sub.Provider != "gemini" {
			t.Errorf("sub Provider: got %q, want gemini", sub.Provider)
		}
	})

	// Case 2: top-level anthropic, sub-block explicitly gemini.
	t.Run("mixed_providers", func(t *testing.T) {
		shared := &LLMConfig{Provider: "anthropic", Endpoint: anthropicURL}
		sub := &LLMProviderConfig{Provider: "gemini"}
		inheritLLMDefaults(sub, shared)
		if sub.Endpoint != "" {
			t.Errorf("sub Endpoint: got %q, want empty", sub.Endpoint)
		}
	})

	// Sanity: anthropic sub-block still inherits the anthropic endpoint.
	t.Run("anthropic_inherits", func(t *testing.T) {
		shared := &LLMConfig{Provider: "anthropic", Endpoint: anthropicURL}
		sub := &LLMProviderConfig{}
		inheritLLMDefaults(sub, shared)
		if sub.Endpoint != anthropicURL {
			t.Errorf("sub Endpoint: got %q, want %q", sub.Endpoint, anthropicURL)
		}
	})

	// Sanity: a custom (non-Anthropic-default) endpoint still inherits — the
	// guard only filters the specific Anthropic default URL.
	t.Run("custom_endpoint_inherits", func(t *testing.T) {
		shared := &LLMConfig{Provider: "gemini", Endpoint: "https://my-gateway.internal/v1"}
		sub := &LLMProviderConfig{}
		inheritLLMDefaults(sub, shared)
		if sub.Endpoint != "https://my-gateway.internal/v1" {
			t.Errorf("sub Endpoint: got %q, want custom URL", sub.Endpoint)
		}
	})
}
