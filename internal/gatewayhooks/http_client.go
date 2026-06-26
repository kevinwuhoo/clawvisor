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
	return &HTTPClient{
		client: client,
		now:    time.Now,
	}
}

func (c *HTTPClient) Call(ctx context.Context, cfg config.GatewayHookHandlerConfig, payload HookRequest) (HookResponse, HandlerSummary, error) {
	start := time.Now()
	summary := HandlerSummary{Name: cfg.Name, FailureMode: normalizedFailureMode(cfg.FailureMode)}

	body, err := json.Marshal(payload)
	if err != nil {
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		summary.DurationMS = time.Since(start).Milliseconds()
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
			summary.DurationMS = time.Since(start).Milliseconds()
			summary.Error = err.Error()
			return HookResponse{}, summary, err
		}
		timestamp := fmt.Sprintf("%d", c.now().Unix())
		req.Header.Set("X-Clawvisor-Hook-Timestamp", timestamp)
		req.Header.Set("X-Clawvisor-Hook-Signature", signHookBody(secret, timestamp, body))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHookResponseBytes))
		err := fmt.Errorf("hook %q returned status %d", cfg.Name, resp.StatusCode)
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxHookResponseBytes+1))
	if err != nil {
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}
	if len(responseBody) > maxHookResponseBytes {
		err := fmt.Errorf("hook %q response exceeds %d bytes", cfg.Name, maxHookResponseBytes)
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}

	var hookResp HookResponse
	if err := json.Unmarshal(responseBody, &hookResp); err != nil {
		summary.DurationMS = time.Since(start).Milliseconds()
		summary.Error = err.Error()
		return HookResponse{}, summary, err
	}

	summary.DurationMS = time.Since(start).Milliseconds()
	summary.Decision = hookResp.Decision
	summary.UpdatedToolResponse = hookResp.UpdatedToolResponse != nil
	summary.Metadata = hookResp.AuditMetadata
	return hookResp, summary, nil
}

func signHookBody(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func normalizedFailureMode(mode string) string {
	if mode == "fail_open" {
		return "fail_open"
	}
	return "fail_closed"
}
