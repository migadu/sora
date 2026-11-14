package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestWarnUnusedConfigOptions(t *testing.T) {
	tests := []struct {
		name         string
		serverConfig ServerConfig
		wantWarnings []string // Substrings expected in warnings
	}{
		{
			name: "IMAP with supported_extensions",
			serverConfig: ServerConfig{
				Type:                "imap",
				Name:                "imap-test",
				Addr:                ":143",
				SupportedExtensions: []string{"vacation"},
			},
			wantWarnings: []string{"supported_extensions", "ManageSieve"},
		},
		{
			name: "IMAP with remote_addrs",
			serverConfig: ServerConfig{
				Type:        "imap",
				Name:        "imap-test",
				Addr:        ":143",
				RemoteAddrs: []string{"backend1:143"},
			},
			wantWarnings: []string{"remote_addrs", "proxy"},
		},
		{
			name: "POP3 proxy with supported_extensions",
			serverConfig: ServerConfig{
				Type:                "pop3_proxy",
				Name:                "pop3-proxy-test",
				Addr:                ":110",
				RemoteAddrs:         []string{"backend1:110"},
				SupportedExtensions: []string{"vacation"},
			},
			wantWarnings: []string{"supported_extensions", "ManageSieve"},
		},
		{
			name: "ManageSieve with remote_addrs",
			serverConfig: ServerConfig{
				Type:        "managesieve",
				Name:        "managesieve-test",
				Addr:        ":4190",
				RemoteAddrs: []string{"backend1:4190"},
			},
			wantWarnings: []string{"remote_addrs", "proxy"},
		},
		{
			name: "ManageSieve proxy with valid config",
			serverConfig: ServerConfig{
				Type:                "managesieve_proxy",
				Name:                "managesieve-proxy-test",
				Addr:                ":4190",
				RemoteAddrs:         []string{"backend1:4190"},
				SupportedExtensions: []string{"vacation"}, // Valid for managesieve_proxy
			},
			wantWarnings: nil, // No warnings expected
		},
		{
			name: "LMTP proxy with max_script_size",
			serverConfig: ServerConfig{
				Type:          "lmtp_proxy",
				Name:          "lmtp-proxy-test",
				Addr:          ":2525",
				RemoteAddrs:   []string{"backend1:2525"},
				MaxScriptSize: "16kb",
			},
			wantWarnings: []string{"max_script_size", "ManageSieve"},
		},
		{
			name: "Metrics server with remote_addrs",
			serverConfig: ServerConfig{
				Type:        "metrics",
				Name:        "metrics-test",
				Addr:        ":9090",
				RemoteAddrs: []string{"backend1:143"},
			},
			wantWarnings: []string{"remote_addrs", "proxy"},
		},
		{
			name: "IMAP with remote_use_id_command",
			serverConfig: ServerConfig{
				Type:               "imap",
				Name:               "imap-test",
				Addr:               ":143",
				RemoteUseIDCommand: true,
			},
			wantWarnings: []string{"remote_use_id_command", "IMAP proxy"},
		},
		{
			name: "LMTP with remote_use_xclient",
			serverConfig: ServerConfig{
				Type:             "lmtp",
				Name:             "lmtp-test",
				Addr:             ":2525",
				RemoteUseXCLIENT: true,
			},
			wantWarnings: []string{"remote_use_xclient", "LMTP proxy"},
		},
		{
			name: "IMAP with remote_tls_use_starttls",
			serverConfig: ServerConfig{
				Type:                 "imap",
				Name:                 "imap-test",
				Addr:                 ":143",
				RemoteTLSUseStartTLS: true,
			},
			wantWarnings: []string{"remote_tls_use_starttls", "proxy"},
		},
		{
			name: "POP3 proxy with remote_use_xclient",
			serverConfig: ServerConfig{
				Type:             "pop3_proxy",
				Name:             "pop3-proxy-test",
				Addr:             ":110",
				RemoteAddrs:      []string{"backend1:110"},
				RemoteUseXCLIENT: true,
			},
			wantWarnings: []string{"remote_use_xclient", "LMTP proxy"},
		},
		{
			name: "IMAP proxy with remote_use_xclient",
			serverConfig: ServerConfig{
				Type:             "imap_proxy",
				Name:             "imap-proxy-test",
				Addr:             ":143",
				RemoteAddrs:      []string{"backend1:143"},
				RemoteUseXCLIENT: true,
			},
			wantWarnings: []string{"remote_use_xclient", "LMTP proxy"},
		},
		{
			name: "LMTP proxy with remote_use_id_command",
			serverConfig: ServerConfig{
				Type:               "lmtp_proxy",
				Name:               "lmtp-proxy-test",
				Addr:               ":2525",
				RemoteAddrs:        []string{"backend1:2525"},
				RemoteUseIDCommand: true,
			},
			wantWarnings: []string{"remote_use_id_command", "IMAP proxy"},
		},
		{
			// The metrics endpoint does not read PROXY headers (#272).
			name: "metrics with proxy_protocol",
			serverConfig: ServerConfig{
				Type:          "metrics",
				Name:          "metrics-test",
				Addr:          ":9090",
				ProxyProtocol: true,
			},
			wantWarnings: []string{"proxy_protocol", "metrics"},
		},
		{
			name: "IMAP proxy with proxy_protocol",
			serverConfig: ServerConfig{
				Type:          "imap_proxy",
				Name:          "imap-proxy-test",
				Addr:          ":143",
				RemoteAddrs:   []string{"backend1:143"},
				ProxyProtocol: true,
			},
			wantWarnings: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnings []string
			mockLogger := func(format string, args ...any) {
				warning := format
				if len(args) > 0 {
					// Simple sprintf - just for testing
					warning = strings.Replace(format, "%s", "", -1)
					for _, arg := range args {
						if s, ok := arg.(string); ok {
							warning += " " + s
						}
					}
				}
				warnings = append(warnings, warning)
			}

			tt.serverConfig.WarnUnusedConfigOptions(mockLogger)

			if len(tt.wantWarnings) == 0 {
				if len(warnings) > 0 {
					t.Errorf("Expected no warnings, but got: %v", warnings)
				}
			} else {
				if len(warnings) == 0 {
					t.Errorf("Expected warnings containing %v, but got no warnings", tt.wantWarnings)
					return
				}

				// Check that all expected substrings are present in the warnings
				allWarnings := strings.Join(warnings, " ")
				for _, wantSubstr := range tt.wantWarnings {
					if !strings.Contains(allWarnings, wantSubstr) {
						t.Errorf("Expected warning to contain %q, but warnings were: %v", wantSubstr, warnings)
					}
				}
			}
		})
	}
}

func TestWarnUnusedConfigOptions_MultipleIssues(t *testing.T) {
	// Test server with multiple incorrect config options
	serverConfig := ServerConfig{
		Type:                "imap",
		Name:                "imap-test",
		Addr:                ":143",
		SupportedExtensions: []string{"vacation", "regex"},
		RemoteAddrs:         []string{"backend1:143", "backend2:143"},
		MaxScriptSize:       "16kb",
	}

	var warningCount int
	mockLogger := func(format string, args ...any) {
		warningCount++
	}

	serverConfig.WarnUnusedConfigOptions(mockLogger)

	// Should get warnings for both supported_extensions and remote_addrs
	// (MaxScriptSize doesn't trigger a warning for IMAP as we didn't add that check)
	if warningCount < 2 {
		t.Errorf("Expected at least 2 warnings for multiple invalid options, got %d", warningCount)
	}
}

// remote_tls_use_starttls only does anything together with remote_tls: without it the
// backend leg is dialed plaintext and never upgraded. The User API proxy speaks HTTPS to
// its backends and has no STARTTLS at all.
func TestWarnUnusedConfigOptions_RemoteStartTLS(t *testing.T) {
	tests := []struct {
		name         string
		serverConfig ServerConfig
		wantWarning  string // substring of the one expected warning; "" for none
	}{
		{
			name:         "proxy with remote_tls_use_starttls but no remote_tls",
			serverConfig: ServerConfig{Type: "lmtp_proxy", Name: "lmtp-proxy-test", RemoteTLSUseStartTLS: true},
			wantWarning:  "'remote_tls_use_starttls' configured without 'remote_tls'",
		},
		{
			name:         "proxy with remote_tls and remote_tls_use_starttls",
			serverConfig: ServerConfig{Type: "imap_proxy", Name: "imap-proxy-test", RemoteTLS: true, RemoteTLSUseStartTLS: true},
		},
		{
			name: "remote_lookup with remote_tls_use_starttls but no remote_tls",
			serverConfig: ServerConfig{Type: "managesieve_proxy", Name: "sieve-proxy-test", RemoteTLS: true, RemoteTLSUseStartTLS: true,
				RemoteLookup: &RemoteLookupConfig{RemoteTLSUseStartTLS: true}},
			wantWarning: "'remote_lookup.remote_tls_use_starttls' configured without 'remote_lookup.remote_tls'",
		},
		{
			name: "remote_lookup with remote_tls and remote_tls_use_starttls",
			serverConfig: ServerConfig{Type: "pop3_proxy", Name: "pop3-proxy-test",
				RemoteLookup: &RemoteLookupConfig{RemoteTLS: true, RemoteTLSUseStartTLS: true}},
		},
		{
			name:         "user_api_proxy with remote_tls_use_starttls",
			serverConfig: ServerConfig{Type: "user_api_proxy", Name: "user-api-proxy-test", RemoteTLS: true, RemoteTLSUseStartTLS: true},
			wantWarning:  "'remote_tls_use_starttls' configured, but the User API proxy",
		},
		{
			name:         "user_api_proxy with remote_tls_use_starttls but no remote_tls",
			serverConfig: ServerConfig{Type: "user_api_proxy", Name: "user-api-proxy-test", RemoteTLSUseStartTLS: true},
			wantWarning:  "'remote_tls_use_starttls' configured, but the User API proxy",
		},
		{
			name: "user_api_proxy with remote_lookup remote_tls_use_starttls",
			serverConfig: ServerConfig{Type: "user_api_proxy", Name: "user-api-proxy-test", RemoteTLS: true,
				RemoteLookup: &RemoteLookupConfig{RemoteTLS: true, RemoteTLSUseStartTLS: true}},
			wantWarning: "'remote_lookup.remote_tls_use_starttls' configured, but the User API proxy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnings []string
			tt.serverConfig.WarnUnusedConfigOptions(func(format string, args ...any) {
				warnings = append(warnings, fmt.Sprintf(format, args...))
			})
			if tt.wantWarning == "" {
				if len(warnings) > 0 {
					t.Errorf("Expected no warnings, but got: %v", warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], tt.wantWarning) || !strings.Contains(warnings[0], tt.serverConfig.Name) {
				t.Errorf("Expected one warning containing %q for %s, got: %v", tt.wantWarning, tt.serverConfig.Name, warnings)
			}
		})
	}
}

func TestWarnUnusedStartTLS(t *testing.T) {
	supported := map[string]bool{"imap": true, "lmtp": true, "managesieve": true, "pop3": true, "imap_proxy": true, "lmtp_proxy": true, "managesieve_proxy": true, "pop3_proxy": true}
	for _, serverType := range []string{"imap", "pop3", "imap_proxy", "pop3_proxy", "metrics", "http_admin_api", "http_user_api", "lmtp", "managesieve", "lmtp_proxy", "managesieve_proxy"} {
		t.Run(serverType, func(t *testing.T) {
			cfg := ServerConfig{Type: serverType, Name: "listener", TLS: supported[serverType], TLSUseStartTLS: true}
			var warnings []string
			cfg.WarnUnusedConfigOptions(func(format string, args ...any) {
				warnings = append(warnings, fmt.Sprintf(format, args...))
			})
			if supported[serverType] {
				if len(warnings) != 0 {
					t.Fatalf("supported STARTTLS listener warned: %v", warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], "'tls_use_starttls'") || !strings.Contains(warnings[0], "IMAP, LMTP, ManageSieve and POP3 servers and proxies") {
				t.Fatalf("expected accurate unsupported STARTTLS warning, got %v", warnings)
			}
		})
	}
}

// tls_use_starttls without tls is dropped by every server that supports it, so the
// listener comes up plaintext with no STARTTLS; that must be said at startup, not
// only in a debug log.
func TestWarnStartTLSWithoutTLS(t *testing.T) {
	for _, serverType := range []string{"imap", "lmtp", "managesieve", "pop3", "imap_proxy", "lmtp_proxy", "managesieve_proxy", "pop3_proxy"} {
		t.Run(serverType, func(t *testing.T) {
			cfg := ServerConfig{Type: serverType, Name: "listener", TLSUseStartTLS: true}
			var warnings []string
			cfg.WarnUnusedConfigOptions(func(format string, args ...any) {
				warnings = append(warnings, fmt.Sprintf(format, args...))
			})
			if len(warnings) != 1 || !strings.Contains(warnings[0], "without 'tls = true'") {
				t.Fatalf("expected a warning that tls_use_starttls needs tls, got %v", warnings)
			}
		})
	}
}

// tls_verify asks the TLS handshake for a client certificate, so without tls =
// true it does nothing on any listener; that must be said at startup (#416).
func TestWarnTLSVerifyWithoutTLS(t *testing.T) {
	for _, serverType := range []string{"imap", "lmtp", "managesieve", "pop3", "imap_proxy", "lmtp_proxy", "managesieve_proxy", "pop3_proxy", "user_api_proxy", "http_admin_api", "http_user_api"} {
		t.Run(serverType, func(t *testing.T) {
			for _, withTLS := range []bool{false, true} {
				cfg := ServerConfig{Type: serverType, Name: "listener", TLS: withTLS, TLSVerify: true}
				var warnings []string
				cfg.WarnUnusedConfigOptions(func(format string, args ...any) {
					warnings = append(warnings, fmt.Sprintf(format, args...))
				})
				if withTLS && len(warnings) != 0 {
					t.Fatalf("tls_verify with tls = true warned: %v", warnings)
				}
				if !withTLS && (len(warnings) != 1 || !strings.Contains(warnings[0], "'tls_verify'") || !strings.Contains(warnings[0], "without 'tls = true'")) {
					t.Fatalf("expected a warning that tls_verify needs tls, got %v", warnings)
				}
			}
		})
	}
}
