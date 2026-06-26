package gatewayhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/clawvisor/clawvisor/pkg/adapters"
	"github.com/clawvisor/clawvisor/pkg/config"
)

func TestHTTPHookClientSignsRequest(t *testing.T) {
	t.Setenv("CLAWVISOR_TEST_HOOK_SECRET", "hook-secret")

	var signatureObserved string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readAllForTest(t, r.Body)
		t.Cleanup(func() { _ = r.Body.Close() })

		if got := r.Header.Get("X-Clawvisor-Hook-Name"); got != "privacy-filter" {
			t.Fatalf("X-Clawvisor-Hook-Name = %q, want privacy-filter", got)
		}
		if got := r.Header.Get("X-Clawvisor-Hook-Event"); got != EventGatewayPostToolCall {
			t.Fatalf("X-Clawvisor-Hook-Event = %q, want %s", got, EventGatewayPostToolCall)
		}
		timestamp := r.Header.Get("X-Clawvisor-Hook-Timestamp")
		if timestamp != "1782500000" {
			t.Fatalf("X-Clawvisor-Hook-Timestamp = %q, want 1782500000", timestamp)
		}

		signatureObserved = r.Header.Get("X-Clawvisor-Hook-Signature")
		expectedSignature := expectedHookSignature("hook-secret", timestamp, body)
		if signatureObserved != expectedSignature {
			t.Fatalf("X-Clawvisor-Hook-Signature = %q, want %q", signatureObserved, expectedSignature)
		}

		if err := json.NewEncoder(w).Encode(HookResponse{
			HookEventName: EventGatewayPostToolCall,
			Decision:      DecisionContinue,
			UpdatedToolResponse: &adapters.Result{
				Summary: "redacted",
			},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.Client())
	client.now = func() time.Time { return time.Unix(1782500000, 0) }

	resp, _, err := client.Call(context.Background(), config.GatewayHookHandlerConfig{
		Name:                "privacy-filter",
		Type:                "http",
		URL:                 srv.URL,
		TimeoutSeconds:      5,
		AllowResponseUpdate: true,
		SecretEnv:           "CLAWVISOR_TEST_HOOK_SECRET",
	}, HookRequest{
		HookEventName: EventGatewayPostToolCall,
		HookName:      "privacy-filter",
		Service:       "google.gmail",
		Action:        "get_message",
		ToolName:      "gmail_get_message",
		ToolResponse:  &adapters.Result{Summary: "sensitive"},
	})
	if err != nil {
		t.Fatalf("Call returned error: %v", err)
	}
	if signatureObserved == "" {
		t.Fatal("expected signature to be observed")
	}
	if resp.UpdatedToolResponse == nil {
		t.Fatal("UpdatedToolResponse is nil")
	}
	if got := resp.UpdatedToolResponse.Summary; got != "redacted" {
		t.Fatalf("UpdatedToolResponse.Summary = %q, want redacted", got)
	}
}

func TestHTTPHookClientRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bad gateway"))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.Client())
	_, _, err := client.Call(context.Background(), config.GatewayHookHandlerConfig{
		Name: "bad-hook",
		Type: "http",
		URL:  srv.URL,
	}, HookRequest{HookEventName: EventGatewayPostToolCall, HookName: "bad-hook"})
	if err == nil {
		t.Fatal("Call returned nil error, want non-2xx error")
	}
}

func TestHTTPHookClientRejectsInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.Client())
	_, _, err := client.Call(context.Background(), config.GatewayHookHandlerConfig{
		Name: "bad-json",
		Type: "http",
		URL:  srv.URL,
	}, HookRequest{HookEventName: EventGatewayPostToolCall, HookName: "bad-json"})
	if err == nil {
		t.Fatal("Call returned nil error, want invalid JSON error")
	}
}

func TestHTTPHookClientSanitizesTransportError(t *testing.T) {
	client := NewHTTPClient(&http.Client{Transport: erringRoundTripper{
		err: errors.New("dial failed for https://hook.example/hook?token=secret-token"),
	}})

	_, summary, err := client.Call(context.Background(), config.GatewayHookHandlerConfig{
		Name: "leaky-hook",
		Type: "http",
		URL:  "https://hook.example/hook?token=secret-token",
	}, HookRequest{HookEventName: EventGatewayPostToolCall, HookName: "leaky-hook"})
	if err == nil {
		t.Fatal("Call returned nil error, want transport error")
	}
	for _, got := range []string{err.Error(), summary.Error} {
		if strings.Contains(got, "secret-token") || strings.Contains(got, "hook.example") {
			t.Fatalf("transport error leaked hook URL: %q", got)
		}
		if !strings.Contains(got, `hook "leaky-hook" request failed`) {
			t.Fatalf("transport error = %q, want sanitized hook request failure", got)
		}
	}
}

type erringRoundTripper struct {
	err error
}

func (rt erringRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, rt.err
}

func readAllForTest(t *testing.T, r io.Reader) []byte {
	t.Helper()
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

func expectedHookSignature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
