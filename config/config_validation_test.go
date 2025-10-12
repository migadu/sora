package config

import (
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnings []string
			mockLogger := func(format string, args ...interface{}) {
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
	mockLogger := func(format string, args ...interface{}) {
		warningCount++
	}

	serverConfig.WarnUnusedConfigOptions(mockLogger)

	// Should get warnings for both supported_extensions and remote_addrs
	// (MaxScriptSize doesn't trigger a warning for IMAP as we didn't add that check)
	if warningCount < 2 {
		t.Errorf("Expected at least 2 warnings for multiple invalid options, got %d", warningCount)
	}
}
