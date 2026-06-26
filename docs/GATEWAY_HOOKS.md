# Gateway Hooks

Gateway hooks are external HTTP handlers that Clawvisor can call during native gateway execution. They let an operator run site-specific processing around gateway results without coupling Clawvisor core to any one downstream product or policy engine.

V1 supports one event: `GatewayPostToolCall`.

`GatewayPostToolCall` fires after an adapter succeeds and before the result is used for HTTP responses, callbacks, or chain-context extraction. A matching hook can observe the adapter result, return an updated result, or block result egress.

Hooks are optional. When `gateway_hooks.enabled` is false or no matcher applies, the gateway result follows the normal execution path.

## Configuration

Configure hooks in the main Clawvisor YAML config:

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

The same structure can be supplied through `CLAWVISOR_GATEWAY_HOOKS_JSON`. When that environment variable is set to non-whitespace content, it replaces the file config for `gateway_hooks`.

Handler fields:

- `name`: Stable handler name. Included in hook headers, request bodies, and audit metadata.
- `type`: Only `http` is supported in v1.
- `url`: HTTP endpoint that receives the hook request.
- `timeout_seconds`: Per-request timeout. `0` uses the default 10-second timeout. Negative values are invalid.
- `failure_mode`: `fail_closed`, `fail_open`, or empty. Empty behaves like `fail_closed`.
- `allow_response_update`: Whether this handler may return `updated_tool_response`.
- `secret_env`: Optional environment variable containing the HMAC signing secret. If set, the variable must exist and be non-empty when config is validated.

## Matcher Basics

Each `GatewayPostToolCall` entry has one matcher and one or more handlers. Entries are evaluated in config order. If the matcher applies, handlers in that entry run in order. If a handler returns an updated response, later matching handlers receive that updated response.

Matcher fields:

- `service`: Exact service ID, pipe-separated service list, or `*`.
- `action`: Exact action, pipe-separated action list, or `*`.

Service aliases are normalized before matching. For example, `google.gmail:personal` matches `google.gmail`.

Examples:

```yaml
matcher:
  service: "google.gmail|google.drive"
  action: "get_message|list_files"
```

```yaml
matcher:
  service: "*"
  action: "*"
```

## HTTP Request

Clawvisor sends a JSON `POST` to each matching handler.

Headers:

- `Content-Type: application/json`
- `X-Clawvisor-Hook-Name: <handler name>`
- `X-Clawvisor-Hook-Event: GatewayPostToolCall`
- `X-Clawvisor-Hook-Timestamp: <unix seconds>` when `secret_env` is set
- `X-Clawvisor-Hook-Signature: sha256=<hex hmac>` when `secret_env` is set

Request body schema:

```json
{
  "hook_event_name": "GatewayPostToolCall",
  "hook_name": "privacy-filter",
  "request_id": "req-abc-123",
  "audit_id": "audit-uuid",
  "user_id": "user-uuid",
  "agent_id": "agent-uuid",
  "task_id": "task-uuid",
  "session_id": "session-uuid",
  "service": "google.gmail",
  "action": "get_message",
  "tool_name": "google.gmail.get_message",
  "tool_input": {
    "params": {
      "message_id": "msg-123"
    },
    "reason": "User asked me to summarize the message"
  },
  "tool_response": {
    "summary": "Message from Alice",
    "data": {
      "subject": "Hello",
      "body": "..."
    },
    "meta": {}
  }
}
```

`tool_response` is the adapter `Result` shape: `summary`, `data`, and optional `meta`. Hook services should treat the entire request as sensitive. Do not log raw hook payloads unless an operator has explicitly built a safe redaction pipeline for those logs.

## HMAC Auth

When a handler config sets `secret_env`, Clawvisor signs the exact JSON request body with HMAC-SHA256.

Signature input:

```text
<timestamp>.<raw request body>
```

Signature header:

```text
X-Clawvisor-Hook-Signature: sha256=<hex-encoded HMAC-SHA256>
```

The hook service should:

- Read the raw body bytes before parsing JSON.
- Recompute the signature using the shared secret from the configured environment variable.
- Compare signatures in constant time.
- Enforce a small timestamp freshness window to limit replay risk.

The signing secret is not sent in the request. Rotate it like any other service secret.

## HTTP Response

Handlers must return a 2xx status with a JSON body.

Response body schema:

```json
{
  "hook_event_name": "GatewayPostToolCall",
  "decision": "continue",
  "updated_tool_response": {
    "summary": "Message from [PRIVATE_PERSON]",
    "data": {
      "subject": "Hello",
      "body": "..."
    },
    "meta": {
      "redaction": {
        "applied": true
      }
    }
  },
  "audit_metadata": {
    "privacy_filter": {
      "applied": true,
      "items_redacted": 2
    }
  }
}
```

Response fields:

- `hook_event_name`: Must be `GatewayPostToolCall`.
- `decision`: Must be `continue` or `block`.
- `updated_tool_response`: Optional adapter `Result`. Allowed only when `allow_response_update: true`.
- `audit_metadata`: Optional structured metadata for the audit log. It should contain counts, booleans, or other aggregate facts, not raw downstream content.

When `decision` is `continue`, Clawvisor keeps processing. If `updated_tool_response` is present and allowed, Clawvisor replaces the current result with that value. The hook-updated result is the only result used for HTTP responses, callbacks, and chain-context extraction.

When `decision` is `block`, Clawvisor stops processing and returns a gateway error with `code: "HOOK_BLOCKED"` instead of returning the adapter result.

## Failure Modes

Hook failures include:

- Timeout.
- Transport failure.
- Non-2xx HTTP status.
- Response body larger than the 1 MiB supported limit.
- Invalid JSON.
- Invalid `hook_event_name`.
- Invalid `decision`.
- `updated_tool_response` returned when `allow_response_update` is false.

`fail_closed` prevents raw result egress on hook failure. Clawvisor returns a gateway error with `status: "error"` and `code: "HOOK_FAILED"`. If a hook explicitly blocks, Clawvisor returns `status: "error"` and `code: "HOOK_BLOCKED"`.

`fail_open` records failure metadata and returns the current result, but skips chain-context extraction for that result. Unauthorized mutation is always forced closed even if the handler is configured as `fail_open`.

## Audit Metadata

Clawvisor stores aggregate gateway hook metadata in `audit_log.filters_applied` under a `gateway_hooks` object:

```json
{
  "gateway_hooks": {
    "GatewayPostToolCall": [
      {
        "name": "privacy-filter",
        "decision": "continue",
        "duration_ms": 15,
        "updated_tool_response": true,
        "failure_mode": "fail_closed",
        "metadata": {
          "field_0": {
            "field_0": true,
            "field_1": 2
          }
        }
      }
    ]
  }
}
```

`audit_metadata` keys are sanitized before storage. Numeric, boolean, and null primitive values are preserved. Arrays and nested objects are preserved recursively, but object keys are replaced with stable `field_N` names. Strings and unsupported value types are stored as `"[omitted]"`. This keeps audit rows useful for debugging and reporting without treating hook-provided metadata as a safe place for raw content.

## Privacy Filter Example

A privacy-filter hook is one possible use of `GatewayPostToolCall`: the hook service receives a tool result, redacts sensitive values, returns an `updated_tool_response`, and stores aggregate redaction counts in `audit_metadata`.

This is only an example. Core Clawvisor is decoupled from OpenAI Privacy Filter and from any specific privacy-filter service. Operators can plug in other HTTP handlers that follow the same protocol.

Gateway hooks are not a compliance guarantee. A privacy-filter hook is a data minimization mitigation, not proof that every sensitive value has been removed or that a deployment satisfies any regulatory requirement.

## Operational Guidance

Treat hook services as trusted security-sensitive components because they can see and mutate adapter results before those results reach agents.

- Bind hook services to localhost or a private network whenever possible.
- Use `secret_env` for every non-local hook.
- Keep hook timeouts short.
- Prefer `fail_closed` for hooks that are meant to prevent sensitive result egress.
- Do not log credentials, tokens, raw hook payloads, hook responses, or full downstream request and response bodies.
- Keep hook response mutations narrow and predictable.
