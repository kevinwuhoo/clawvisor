package gatewayhooks

import (
	"strings"

	"github.com/clawvisor/clawvisor/pkg/config"
)

func MatchGatewayCall(m config.GatewayHookMatcherConfig, service, action string) bool {
	return matchServiceList(m.Service, service) && matchTokenList(m.Action, action)
}

func normalizeService(service string) string {
	service = strings.TrimSpace(service)
	if idx := strings.Index(service, ":"); idx >= 0 {
		service = service[:idx]
	}
	return service
}

func matchServiceList(pattern, service string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "*" {
		return true
	}

	service = normalizeService(service)
	for _, token := range strings.Split(pattern, "|") {
		if normalizeService(token) == service {
			return true
		}
	}
	return false
}

func matchTokenList(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == "*" {
		return true
	}
	for _, token := range strings.Split(pattern, "|") {
		if strings.TrimSpace(token) == value {
			return true
		}
	}
	return false
}
