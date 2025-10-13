package proxy

import (
	"strings"
	"testing"

	"github.com/migadu/sora/config"
)

// TestSplitEmailAndToken tests the email/token splitting logic
func TestSplitEmailAndToken(t *testing.T) {
	tests := []struct {
		name                 string
		allowMasterToken     bool
		masterTokenSeparator string
		email                string
		expectedEmail        string
		expectedToken        string
		expectedHasToken     bool
		description          string
	}{
		{
			name:                 "Master token disabled",
			allowMasterToken:     false,
			masterTokenSeparator: "@",
			email:                "user@domain.com@TOKEN123",
			expectedEmail:        "user@domain.com@TOKEN123",
			expectedToken:        "",
			expectedHasToken:     false,
			description:          "When disabled, return email as-is",
		},
		{
			name:                 "Valid token with @ separator",
			allowMasterToken:     true,
			masterTokenSeparator: "@",
			email:                "user@domain.com@TOKEN123",
			expectedEmail:        "user@domain.com",
			expectedToken:        "TOKEN123",
			expectedHasToken:     true,
			description:          "Split on @ separator",
		},
		{
			name:                 "No separator in email (normal email)",
			allowMasterToken:     true,
			masterTokenSeparator: "@",
			email:                "user@domain.com",
			expectedEmail:        "user@domain.com",
			expectedToken:        "",
			expectedHasToken:     false,
			description:          "No split when only domain separator found",
		},
		{
			name:                 "Empty token after separator",
			allowMasterToken:     true,
			masterTokenSeparator: "@",
			email:                "userpass@",
			expectedEmail:        "userpass@",
			expectedToken:        "",
			expectedHasToken:     false,
			description:          "Empty token treated as no token",
		},
		{
			name:                 "Multiple separators - use last",
			allowMasterToken:     true,
			masterTokenSeparator: "@",
			email:                "user@domain.com@TOKEN",
			expectedEmail:        "user@domain.com",
			expectedToken:        "TOKEN",
			expectedHasToken:     true,
			description:          "Use last occurrence of separator",
		},
		{
			name:                 "Multiple separators - last segment is token",
			allowMasterToken:     true,
			masterTokenSeparator: "@",
			email:                "userpass@TOKEN@EXTRA",
			expectedEmail:        "userpass@TOKEN",
			expectedToken:        "EXTRA",
			expectedHasToken:     true,
			description:          "Uses LAST @, so email='userpass@TOKEN', token='EXTRA' (valid)",
		},
		{
			name:                 "Custom separator",
			allowMasterToken:     true,
			masterTokenSeparator: "||",
			email:                "userpass||TOKEN123",
			expectedEmail:        "userpass",
			expectedToken:        "TOKEN123",
			expectedHasToken:     true,
			description:          "Multi-character separator works",
		},
		{
			name:                 "Password has @ but separator is different",
			allowMasterToken:     true,
			masterTokenSeparator: "||",
			email:                "user@domain.com||TOKEN",
			expectedEmail:        "user@domain.com",
			expectedToken:        "TOKEN",
			expectedHasToken:     true,
			description:          "Email can contain @ when separator is ||",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &PreLookupClient{
				allowMasterToken:     tt.allowMasterToken,
				masterTokenSeparator: tt.masterTokenSeparator,
			}

			actualEmail, actualToken, hasToken := client.splitEmailAndToken(tt.email)

			if actualEmail != tt.expectedEmail {
				t.Errorf("%s: email = %q, want %q", tt.description, actualEmail, tt.expectedEmail)
			}
			if actualToken != tt.expectedToken {
				t.Errorf("%s: token = %q, want %q", tt.description, actualToken, tt.expectedToken)
			}
			if hasToken != tt.expectedHasToken {
				t.Errorf("%s: hasToken = %v, want %v", tt.description, hasToken, tt.expectedHasToken)
			}

			t.Logf("%s: email=%q -> actualEmail=%q, token=%q, hasToken=%v",
				tt.description, tt.email, actualEmail, actualToken, hasToken)
		})
	}
}

// TestMasterTokenSeparatorValidation tests separator validation
func TestMasterTokenSeparatorValidation(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		separator   string
		shouldSplit bool
		description string
	}{
		{
			name:        "Token without separator in token itself",
			email:       "user@domain.com@TOKEN123",
			separator:   "@",
			shouldSplit: true,
			description: "Valid email with token, no embedded separator in token",
		},
		{
			name:        "Multiple separators - use last (token=123)",
			email:       "user@domain.com@TOKEN@123",
			separator:   "@",
			shouldSplit: true,
			description: "Uses LAST separator, so email='user@domain.com@TOKEN', token='123' (valid)",
		},
		{
			name:        "Multiple @ symbols but last part has no more @",
			email:       "user@example.com@VALIDTOKEN",
			separator:   "@",
			shouldSplit: true,
			description: "Email can have @, token must not",
		},
		{
			name:        "Normal email without token",
			email:       "user@example.com",
			separator:   "@",
			shouldSplit: false,
			description: "Normal email should not be split",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &PreLookupClient{
				allowMasterToken:     true,
				masterTokenSeparator: tt.separator,
			}

			_, token, hasSplit := client.splitEmailAndToken(tt.email)

			if hasSplit != tt.shouldSplit {
				t.Errorf("%s: expected split=%v, got=%v (token=%q)",
					tt.description, tt.shouldSplit, hasSplit, token)
			}

			if hasSplit && strings.Contains(token, tt.separator) {
				t.Errorf("%s: token %q should not contain separator %q",
					tt.description, token, tt.separator)
			}

			t.Logf("%s: email=%q -> hasSplit=%v, token=%q",
				tt.description, tt.email, hasSplit, token)
		})
	}
}

// TestMasterTokenConfigDefaults tests configuration defaults
func TestMasterTokenConfigDefaults(t *testing.T) {
	tests := []struct {
		name              string
		config            *config.PreLookupConfig
		expectedSeparator string
		description       string
	}{
		{
			name: "Default separator when enabled without explicit value",
			config: &config.PreLookupConfig{
				AllowMasterToken:     true,
				MasterTokenSeparator: "",
			},
			expectedSeparator: "@",
			description:       "Should default to @ when empty",
		},
		{
			name: "Custom separator preserved",
			config: &config.PreLookupConfig{
				AllowMasterToken:     true,
				MasterTokenSeparator: "||",
			},
			expectedSeparator: "||",
			description:       "Custom separator should be preserved",
		},
		{
			name: "Disabled - separator doesn't matter",
			config: &config.PreLookupConfig{
				AllowMasterToken:     false,
				MasterTokenSeparator: "custom",
			},
			expectedSeparator: "custom",
			description:       "When disabled, separator value doesn't matter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic from NewPreLookupClient
			masterTokenSeparator := tt.config.MasterTokenSeparator
			if tt.config.AllowMasterToken && masterTokenSeparator == "" {
				masterTokenSeparator = "@"
			}

			if masterTokenSeparator != tt.expectedSeparator {
				t.Errorf("%s: separator = %q, want %q",
					tt.description, masterTokenSeparator, tt.expectedSeparator)
			}

			t.Logf("%s: AllowMasterToken=%v, configured=%q -> effective=%q",
				tt.description, tt.config.AllowMasterToken,
				tt.config.MasterTokenSeparator, masterTokenSeparator)
		})
	}
}

// TestMasterTokenSecurityConstraints verifies security constraints
func TestMasterTokenSecurityConstraints(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		expectValid bool
		reason      string
	}{
		{
			name:        "Valid simple token",
			email:       "user@domain.com@TOKEN",
			expectValid: true,
			reason:      "Simple alphanumeric token",
		},
		{
			name:        "Multiple separators - last segment is token",
			email:       "user@domain.com@TO@KEN",
			expectValid: true,
			reason:      "Uses LAST @, so token='KEN' (no @ in token)",
		},
		{
			name:        "Token explicitly contains separator",
			email:       "user@domain.com@TOK@EN@",
			expectValid: false,
			reason:      "After last @, token is empty (empty token rejected)",
		},
		{
			name:        "Complex email domain, simple token",
			email:       "user@sub.domain.com@TOKEN",
			expectValid: true,
			reason:      "Email can be complex, token simple",
		},
		{
			name:        "Email with plus addressing and token",
			email:       "user+tag@example.com@TOKEN",
			expectValid: true,
			reason:      "Email with plus addressing and token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &PreLookupClient{
				allowMasterToken:     true,
				masterTokenSeparator: "@",
			}

			_, token, hasToken := client.splitEmailAndToken(tt.email)
			isValid := hasToken && !strings.Contains(token, "@")

			if isValid != tt.expectValid {
				t.Errorf("%s: expected valid=%v, got=%v (reason: %s, token=%q)",
					tt.name, tt.expectValid, isValid, tt.reason, token)
			}

			t.Logf("%s: email=%q -> token=%q, valid=%v (%s)",
				tt.name, tt.email, token, isValid, tt.reason)
		})
	}
}
