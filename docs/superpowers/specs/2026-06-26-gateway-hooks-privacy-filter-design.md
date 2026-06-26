# Gateway External Hooks And Privacy Filter Design

Status: proposed
Date: 2026-06-26

## Summary

Add a generic external HTTP hook system for the native Clawvisor gateway. The
first supported event is `GatewayPostToolCall`, which fires after a gateway
adapter successfully executes and before the adapter result is returned to any
caller-controlled destination.

The first hook user is an external privacy-filter service. Clawvisor sends the
adapter result to the hook service, the service returns an updated result with
sensitive content redacted, and Clawvisor returns only the updated result to the
agent, callback URL, and chain-context extraction flow.

This design keeps Clawvisor core decoupled from OpenAI Privacy Filter. Core
owns the hook lifecycle, matching, authentication, timeout, failure policy,
result mutation contract, and audit metadata. The privacy-filter sidecar owns
redaction logic and model dependencies.

## Motivation

Clawvisor already centralizes native API access through gateway adapters. This
is the right place to protect downstream response data because the agent never
sees adapter credentials and the gateway controls every normal egress path for
adapter results.

A tangible flow:

1. An agent asks to fetch a Gmail message.
2. The user approves the task or one-off request.
3. Clawvisor injects credentials and executes `google.gmail.get_message`.
4. The `GatewayPostToolCall` hook sends the adapter result to an external
   privacy-filter service.
5. The hook service returns an updated, redacted result.
6. Clawvisor returns the redacted result to the caller and records aggregate
   hook metadata in audit.

This is a proof of concept for data minimization, not a HIPAA compliance
boundary or anonymization guarantee.

## Inspirations

Codex and Claude Code both expose event-oriented hook systems with matchers and
post-tool-use semantics. Clawvisor should borrow the durable shape, but adapt it
to the gateway model:

- Event names are explicit and stable.
- Hooks are matched by tool/service/action.
- Handlers run outside the core process.
- Hook requests and responses are structured JSON.
- A post-tool-call hook can replace the tool response before the model sees it.
- Timeouts and hook failures are controlled by policy.

Clawvisor's native "tool" is a gateway adapter action, not a shell command or
MCP tool call. In v1, the event is scoped to adapter results only.

## Goals

- Define a generic external HTTP hook API for gateway adapter results.
- Add one event, `GatewayPostToolCall`.
- Allow hooks to replace the adapter result before response, callback, and
  chain extraction.
- Keep privacy filtering outside the Clawvisor repository and core binary.
- Support service/action matchers.
- Support per-handler timeout and failure policy.
- Authenticate Clawvisor-to-hook requests with an optional shared-secret HMAC.
- Store only aggregate hook metadata in `audit_log.filters_applied`.
- Fail closed by default for privacy-filter deployments.

## Non-Goals

- Do not add an in-process Go privacy-filter dependency.
- Do not vendor or submodule OpenAI Privacy Filter.
- Do not add proxy-lite, resolver, or transcript-history hooks in v1.
- Do not add command-execution hooks in v1.
- Do not add UI management for hooks in v1.
- Do not expose credentials, vault contents, OAuth tokens, or raw audit bodies
  to hook services.
- Do not claim compliance guarantees from the privacy-filter hook.

## Event Model

V1 supports one event:

```text
GatewayPostToolCall
```

The event fires after:

- Gateway auth, restrictions, task-scope checks, approval checks, and optional
  intent verification have passed.
- Vault credential injection has completed.
- `adapter.Execute(...)` has returned successfully.
- Existing adapter response middleware, such as MCP response middleware, has
  run.

The event fires before:

- HTTP gateway responses are written.
- Agent callback payloads are delivered.
- Chain-context extraction starts.
- Any gateway result is visible to the caller LLM.

The event does not fire when adapter execution fails. Adapter errors continue to
use the existing gateway error path.

## Configuration

Add a top-level `gateway_hooks` config section.

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

Defaults:

- `gateway_hooks.enabled`: `false`
- event lists: empty
- `timeout_seconds`: 10
- `failure_mode`: `fail_closed`
- `allow_response_update`: `false`
- `secret_env`: empty, meaning unsigned requests

Only `type: "http"` is supported in v1.

### Matching

The matcher selects which gateway calls trigger the hook entry.

V1 matcher fields:

- `service`: exact service ID, `*`, or a pipe-separated list such as
  `google.gmail|google.drive`
- `action`: exact action, `*`, or a pipe-separated list such as
  `get_message|list_messages`

Service aliases are normalized before matching. For example,
`google.gmail:personal` matches `google.gmail`.

If multiple hook entries match the same event, they run in config order. Within
one entry, handlers run in config order.

## Hook Request

Clawvisor sends a JSON POST to each matched HTTP handler.

```json
{
  "hook_event_name": "GatewayPostToolCall",
  "hook_name": "privacy-filter",
  "request_id": "req_123",
  "audit_id": "audit_123",
  "user_id": "user_123",
  "agent_id": "agent_123",
  "task_id": "task_123",
  "session_id": "session_123",
  "service": "google.gmail",
  "action": "get_message",
  "tool_name": "google.gmail.get_message",
  "tool_input": {
    "params": {
      "message_id": "abc"
    },
    "reason": "User asked me to fetch this email"
  },
  "tool_response": {
    "summary": "Email from Jane Doe...",
    "data": {},
    "meta": {}
  }
}
```

Field notes:

- `tool_response` is the current `adapters.Result` after prior hooks have run.
- `tool_input.params` is the original gateway request params. These may contain
  user data but not injected credentials.
- `reason` is untrusted agent-provided text.
- Credentials, vault bytes, OAuth tokens, callback secrets, and raw audit rows
  are never included.

## Hook Response

A hook service returns JSON:

```json
{
  "hook_event_name": "GatewayPostToolCall",
  "decision": "continue",
  "updated_tool_response": {
    "summary": "Email from [PRIVATE_PERSON]...",
    "data": {},
    "meta": {
      "redaction": {
        "applied": true,
        "backend": "openai_privacy_filter"
      }
    }
  },
  "audit_metadata": {
    "privacy_filter": {
      "applied": true,
      "items_sent": 4,
      "items_redacted": 2,
      "labels": {
        "private_person": 1,
        "private_email": 1
      }
    }
  }
}
```

V1 decisions:

- `continue`: proceed to the next hook or gateway egress.
- `block`: stop execution and do not return the adapter result.

`updated_tool_response` is honored only when the handler config sets
`allow_response_update: true`. If a handler returns `updated_tool_response`
without that permission, the response is rejected as a hook protocol error.

`audit_metadata` must be JSON-serializable and should contain aggregate counts,
labels, backend names, and status flags only. It must not contain raw tool
response text, raw redacted text, raw spans, credentials, or tokens.

## Authentication

If `secret_env` is set, Clawvisor reads the named environment variable and
signs each hook request.

Headers:

```text
Content-Type: application/json
X-Clawvisor-Hook-Name: privacy-filter
X-Clawvisor-Hook-Event: GatewayPostToolCall
X-Clawvisor-Hook-Timestamp: 1782500000
X-Clawvisor-Hook-Signature: sha256=<hex hmac>
```

Signature input:

```text
<timestamp>.<raw request body bytes>
```

Signature algorithm:

```text
HMAC-SHA256(secret, signature_input)
```

The hook service should reject requests when:

- The signature is missing and a secret is configured.
- The signature is invalid.
- The timestamp is outside a five-minute freshness window.
- The content type is not JSON.

This authenticates Clawvisor to the hook service. It is not a substitute for
network isolation. Privacy-filter services should still bind to localhost or a
private Docker network for the proof of concept.

If `secret_env` is set while `gateway_hooks.enabled` is true and the named
environment variable is empty or missing, Clawvisor should treat the hook
configuration as invalid at startup. A configured signed hook must not silently
fall back to unsigned requests.

## Failure Semantics

Per handler, `failure_mode` controls what Clawvisor does when the hook cannot
produce a valid `continue` response.

`decision: "block"` is honored regardless of `failure_mode`. It always prevents
the current adapter result from reaching the caller and returns `HOOK_BLOCKED`.

`fail_closed`:

- Timeout, connection error, non-2xx response, invalid JSON, schema mismatch,
  or unauthorized mutation prevents raw result egress.
- Clawvisor records hook failure metadata.
- Clawvisor returns a gateway error with code `HOOK_FAILED`.
- Chain-context extraction is skipped.
- Callback delivery does not include the raw result.

`fail_open`:

- Clawvisor records hook failure metadata.
- Clawvisor continues with the current result.
- Chain-context extraction is skipped for any result that had a matching hook
  failure, even though the HTTP response or callback may continue. This avoids
  sending potentially unfiltered downstream data into the LLM extraction path.

Privacy-filter deployments should use `fail_closed`.

## Audit Behavior

Clawvisor should merge hook summaries into the existing
`audit_log.filters_applied` column.

Example:

```json
{
  "gateway_hooks": {
    "GatewayPostToolCall": [
      {
        "name": "privacy-filter",
        "decision": "continue",
        "duration_ms": 137,
        "updated_tool_response": true,
        "metadata": {
          "privacy_filter": {
            "applied": true,
            "items_sent": 4,
            "items_redacted": 2,
            "labels": {
              "private_person": 1
            }
          }
        }
      }
    ]
  }
}
```

Audit metadata must not include raw downstream response text. If a hook returns
unsafe audit metadata, Clawvisor should drop or reject that metadata rather than
persist it. The first implementation can enforce this by schema and size limits,
not by trying to classify arbitrary strings.

## Gateway Wiring

The hook runner should live above `executeAdapterRequest`, not inside it.

`executeAdapterRequest` should remain responsible for:

- Adapter resolution.
- Vault credential lookup.
- Service config lookup.
- `adapter.Execute(...)`.
- Existing adapter response middleware.

A new shared helper should run hooks with full gateway context:

```text
runGatewayPostToolCallHooks(ctx, context, result) -> updated result, metadata, error
```

Hooked paths:

- Auto-execute path in `internal/api/handlers/gateway.go`
- Approved synchronous execution in `internal/api/handlers/gateway.go`
- Async approval callback path in `internal/api/handlers/approvals.go`
- Pending activation re-execution callback path in
  `internal/api/handlers/services.go`

For successful adapter calls, the result used by HTTP response, callback, and
chain extraction must be the hook-updated result.

## Privacy-Filter Sidecar

The privacy-filter sidecar is a separate service that implements the generic
hook protocol.

Suggested route:

```text
POST /v1/hooks/gateway/post-tool-call
GET  /healthz
```

Behavior:

- Verify HMAC signatures when configured.
- Walk `tool_response.summary`, `tool_response.data`, and selected
  `tool_response.meta` strings.
- Send eligible text to OpenAI Privacy Filter.
- Preserve identifiers and operational fields needed for follow-up calls.
- Return `updated_tool_response` with redacted text.
- Return aggregate-only `audit_metadata`.
- Avoid logging raw hook request or response bodies.

Known limitation:

- This does not redact request params.
- This does not redact proxy-lite resolver responses.
- This does not cover external tools that bypass native Clawvisor gateway
  adapters.

## MVP

The first implementation should include:

- `gateway_hooks` config parsing.
- Event runner for `GatewayPostToolCall`.
- HTTP handler client.
- Matcher support for service/action.
- HMAC request signing via `secret_env`.
- Response schema validation.
- Ordered handler execution.
- `continue` and `block` decisions.
- Result mutation gated by `allow_response_update`.
- Per-handler timeout.
- `fail_closed` and `fail_open`.
- Audit metadata persisted in `filters_applied`.
- Gateway error codes `HOOK_FAILED` and `HOOK_BLOCKED`.
- Documentation showing the privacy-filter sidecar as the first hook service.

## Later Extensions

Future hook events can reuse the same external HTTP handler infrastructure:

- `GatewayPreToolCall`
- `GatewayPostApproval`
- `GatewayPreResponse`
- `TaskApproved`
- `TaskExpanded`
- `GatewayRequestBlocked`

Future handler features:

- Request body size limits per hook.
- Response body size limits per hook.
- Retry policy for idempotent hooks.
- mTLS between Clawvisor and hook services.
- Dashboard visibility for configured hooks and recent failures.
- Hook-specific allowlists for fields included in `tool_input`.
- More expressive matchers for org, agent, task lifetime, or sensitivity.

## Testing Plan

Core tests:

- Config loads `gateway_hooks` defaults and YAML/env overrides.
- Matcher handles exact, wildcard, pipe-separated values, and service aliases.
- HTTP hook client signs requests and validates responses.
- Invalid HMAC configuration fails closed when required.
- `allow_response_update=false` rejects returned `updated_tool_response`.
- `fail_closed` timeout prevents raw adapter result from reaching the caller.
- `fail_open` records failure metadata and returns the current result.
- `decision: "block"` returns `HOOK_BLOCKED`.
- Successful hook replacement updates the gateway HTTP response.
- Successful hook replacement updates callback payloads.
- Successful hook replacement is the input to chain-context extraction.
- Audit metadata is written to `filters_applied`.

Sidecar tests:

- Reject missing or invalid signatures.
- Redact Gmail summary/body fields while preserving message IDs and thread IDs.
- Return aggregate labels and counts only.
- Do not log raw request or response bodies.

## Documentation Updates

When implemented, update:

- `docs/ARCHITECTURE.md`: add gateway hook step after adapter execution.
- `docs/PRIVACY_FILTER.md`: document the privacy-filter hook service.
- `docs/SETUP_DOCKER.md`: show optional sidecar wiring.
- `AGENTS.md`: add gateway hooks and privacy filtering to security-sensitive
  areas because they affect downstream data exposure.

## Acceptance Criteria

- With hooks disabled, gateway behavior is unchanged.
- With a matching privacy-filter hook enabled, Gmail adapter results are
  redacted before HTTP response, callback delivery, and chain extraction.
- With the privacy-filter hook unavailable and `fail_closed`, raw Gmail content
  is not returned.
- The Clawvisor core repository has no OpenAI Privacy Filter dependency.
- The hook protocol can support another external hook service without changing
  gateway handler code.
