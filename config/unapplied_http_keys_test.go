package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// warningsFor returns the startup warnings WarnUnusedConfigOptions logs for s.
func warningsFor(s ServerConfig) []string {
	var warnings []string
	s.WarnUnusedConfigOptions(func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	})
	return warnings
}

// The HTTP servers count no connections per user, and only the User API proxy counts
// them per client address (#697). The metrics listener counts none at all. A block
// that sets a limit its server does not apply is told so at startup; a limit the
// server applies is not warned about.
func TestWarnUnusedConfigOptions_HTTPConnectionLimits(t *testing.T) {
	limits := []struct {
		key string
		set func(*ServerConfig)
	}{
		{"max_connections", func(s *ServerConfig) { s.MaxConnections = 100 }},
		{"max_connections_per_ip", func(s *ServerConfig) { s.MaxConnectionsPerIP = 2 }},
		{"max_connections_per_user", func(s *ServerConfig) { s.MaxConnectionsPerUser = 3 }},
		{"max_connections_per_user_per_ip", func(s *ServerConfig) { s.MaxConnectionsPerUserPerIP = 1 }},
	}
	applied := map[string][]string{
		"metrics":        nil,
		"http_admin_api": {"max_connections"},
		"http_user_api":  {"max_connections"},
		"user_api_proxy": {"max_connections", "max_connections_per_ip"},
	}
	for serverType, appliedKeys := range applied {
		for _, limit := range limits {
			t.Run(serverType+" "+limit.key, func(t *testing.T) {
				s := ServerConfig{Type: serverType, Name: "server-697"}
				limit.set(&s)
				warnings := warningsFor(s)
				if slices.Contains(appliedKeys, limit.key) {
					if len(warnings) > 0 {
						t.Errorf("%s applies '%s' but it was warned about: %v", serverType, limit.key, warnings)
					}
					return
				}
				if len(warnings) != 1 || !strings.Contains(warnings[0], "'"+limit.key+"'") || !strings.Contains(warnings[0], "server-697") {
					t.Errorf("want one warning naming '%s' on server-697, got %v", limit.key, warnings)
				}
			})
		}
	}
}

// allowed_hosts is enforced by the metrics listener and the Admin and User APIs only.
// Every other server type, the User API proxy included, serves every client whatever
// the list says, so a block that sets it is told so at startup (#708).
func TestWarnUnusedConfigOptions_AllowedHostsOnlyOnHTTPServers(t *testing.T) {
	enforcing := []string{"metrics", "http_admin_api", "http_user_api"}
	for _, serverType := range ServerTypes {
		t.Run(serverType, func(t *testing.T) {
			s := ServerConfig{Type: serverType, Name: "server-708", AllowedHosts: []string{"192.0.2.10", "10.0.0.0/8"}}
			warnings := warningsFor(s)
			if slices.Contains(enforcing, serverType) {
				if len(warnings) > 0 {
					t.Errorf("%s enforces 'allowed_hosts' but it was warned about: %v", serverType, warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], "'allowed_hosts'") || !strings.Contains(warnings[0], "server-708") {
				t.Errorf("want one warning naming 'allowed_hosts' on server-708, got %v", warnings)
			}
		})
	}

	// An empty list restricts nothing on any server type: nothing to warn about.
	if warnings := warningsFor(ServerConfig{Type: "user_api_proxy", Name: "server-708", AllowedHosts: []string{}}); len(warnings) > 0 {
		t.Errorf("an empty allowed_hosts was warned about: %v", warnings)
	}
}
