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
		{name: "exact", matcher: config.GatewayHookMatcherConfig{Service: "google.gmail", Action: "get_message"}, service: "google.gmail", action: "get_message", want: true},
		{name: "alias normalized", matcher: config.GatewayHookMatcherConfig{Service: "google.gmail", Action: "get_message"}, service: "google.gmail:personal", action: "get_message", want: true},
		{name: "matcher alias normalized", matcher: config.GatewayHookMatcherConfig{Service: "google.gmail:personal", Action: "get_message"}, service: "google.gmail:personal", action: "get_message", want: true},
		{name: "matcher alias matches base service", matcher: config.GatewayHookMatcherConfig{Service: "google.gmail:personal", Action: "get_message"}, service: "google.gmail", action: "get_message", want: true},
		{name: "pipe list", matcher: config.GatewayHookMatcherConfig{Service: "google.gmail|google.drive", Action: "get_message|list_messages"}, service: "google.gmail", action: "list_messages", want: true},
		{name: "whitespace tokens", matcher: config.GatewayHookMatcherConfig{Service: " google.gmail | google.drive ", Action: " get_message | list_messages "}, service: " google.drive:work ", action: " list_messages ", want: true},
		{name: "wildcard", matcher: config.GatewayHookMatcherConfig{Service: "*", Action: "*"}, service: "slack", action: "list_messages", want: true},
		{name: "service mismatch", matcher: config.GatewayHookMatcherConfig{Service: "google.drive", Action: "*"}, service: "google.gmail", action: "get_message", want: false},
		{name: "action mismatch", matcher: config.GatewayHookMatcherConfig{Service: "*", Action: "get_message"}, service: "google.gmail", action: "list_messages", want: false},
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
