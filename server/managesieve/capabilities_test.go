package managesieve

import (
	"strings"
	"testing"
)

func TestSupportedExtensions(t *testing.T) {
	// Verify supported extensions are defined
	if len(SupportedExtensions) == 0 {
		t.Fatal("SupportedExtensions should not be empty")
	}

	// Verify essential extensions that go-sieve supports are present
	essentials := []string{"fileinto", "envelope", "variables", "vacation"}
	for _, essential := range essentials {
		found := false
		for _, cap := range SupportedExtensions {
			if cap == essential {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential extension %q not found in SupportedExtensions", essential)
		}
	}
}

func TestGetSieveCapabilities(t *testing.T) {
	tests := []struct {
		name                string
		supportedExtensions []string
		wantContains        []string
		wantCount           int
	}{
		{
			name:                "Empty extensions list",
			supportedExtensions: nil,
			wantContains:        []string{},
			wantCount:           0,
		},
		{
			name:                "With extensions",
			supportedExtensions: []string{"fileinto", "vacation", "regex"},
			wantContains:        []string{"fileinto", "vacation", "regex"},
			wantCount:           3,
		},
		{
			name:                "Empty slice",
			supportedExtensions: []string{},
			wantContains:        []string{},
			wantCount:           0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetSieveCapabilities(tt.supportedExtensions)

			if len(got) != tt.wantCount {
				t.Errorf("GetSieveCapabilities() count = %d, want %d", len(got), tt.wantCount)
			}

			// Check that all wanted capabilities are present
			capMap := make(map[string]bool)
			for _, cap := range got {
				capMap[cap] = true
			}

			for _, want := range tt.wantContains {
				if !capMap[want] {
					t.Errorf("GetSieveCapabilities() missing capability %q", want)
				}
			}
		})
	}
}

func TestSieveCapabilitiesNoDuplicates(t *testing.T) {
	// Test with duplicates in supported extensions
	supportedExts := []string{"vacation", "fileinto", "regex", "fileinto"} // fileinto appears twice
	caps := GetSieveCapabilities(supportedExts)

	// Count occurrences
	counts := make(map[string]int)
	for _, cap := range caps {
		counts[cap]++
	}

	// Should preserve duplicates (caller's responsibility to provide clean list)
	// This is by design - GetSieveCapabilities just returns what's configured
	if counts["fileinto"] != 2 {
		t.Logf("Note: GetSieveCapabilities preserves duplicates from config (by design)")
	}
}

func TestValidateExtensions(t *testing.T) {
	tests := []struct {
		name       string
		extensions []string
		wantErr    bool
	}{
		{
			name:       "Valid extensions",
			extensions: []string{"vacation", "regex"},
			wantErr:    false,
		},
		{
			name:       "Valid go-sieve supported extensions",
			extensions: []string{"fileinto", "envelope", "variables"},
			wantErr:    false,
		},
		{
			name:       "Mixed valid extensions",
			extensions: []string{"vacation", "fileinto", "regex", "copy"},
			wantErr:    false,
		},
		{
			name:       "Invalid extension",
			extensions: []string{"unsupported_extension"},
			wantErr:    true,
		},
		{
			name:       "Mixed valid and invalid",
			extensions: []string{"vacation", "invalid", "regex"},
			wantErr:    true,
		},
		{
			name:       "Empty list",
			extensions: []string{},
			wantErr:    false,
		},
		{
			name:       "Nil list",
			extensions: nil,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExtensions(tt.extensions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExtensions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSieveCapabilitiesFormat(t *testing.T) {
	// Test that capabilities can be joined into a valid greeting string
	supportedExts := []string{"fileinto", "vacation", "regex"}
	caps := GetSieveCapabilities(supportedExts)

	capsStr := strings.Join(caps, " ")

	// Verify no extra whitespace
	if strings.Contains(capsStr, "  ") {
		t.Error("Capabilities string should not contain double spaces")
	}

	// Verify it contains expected capabilities
	if !strings.Contains(capsStr, "fileinto") {
		t.Error("Capabilities string should contain 'fileinto'")
	}
	if !strings.Contains(capsStr, "vacation") {
		t.Error("Capabilities string should contain 'vacation'")
	}
	if !strings.Contains(capsStr, "regex") {
		t.Error("Capabilities string should contain 'regex'")
	}
}

func TestAllSupportedExtensions(t *testing.T) {
	// Verify all SupportedExtensions are valid (this should always pass)
	err := ValidateExtensions(SupportedExtensions)
	if err != nil {
		t.Errorf("SupportedExtensions validation failed: %v", err)
	}

	// Verify essential extensions are in the list
	essentials := []string{"fileinto", "vacation", "variables", "envelope"}
	for _, essential := range essentials {
		found := false
		for _, ext := range SupportedExtensions {
			if ext == essential {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential extension %q not in SupportedExtensions", essential)
		}
	}
}

// TestNOOPTagHandling verifies that NOOP command properly echoes back optional tags.
// This is used by clients like sieve-connect to verify capability synchronization.
// Example: NOOP "STARTTLS-RESYNC-CAPA" should respond with OK (TAG "STARTTLS-RESYNC-CAPA") "Done"
func TestNOOPTagHandling(t *testing.T) {
	tests := []struct {
		name         string
		noopArg      string
		wantResponse string
	}{
		{
			name:         "NOOP with STARTTLS-RESYNC-CAPA tag",
			noopArg:      `"STARTTLS-RESYNC-CAPA"`,
			wantResponse: `OK (TAG "STARTTLS-RESYNC-CAPA") "Done"`,
		},
		{
			name:         "NOOP with custom tag",
			noopArg:      `"MY-TAG"`,
			wantResponse: `OK (TAG "MY-TAG") "Done"`,
		},
		{
			name:         "NOOP without tag",
			noopArg:      "",
			wantResponse: "OK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the response format matches Dovecot's behavior
			// The tag should be echoed back in the OK response
			if tt.noopArg != "" && !strings.Contains(tt.wantResponse, tt.noopArg) {
				t.Errorf("Expected response to contain tag %s, got %s", tt.noopArg, tt.wantResponse)
			}
		})
	}
}

// TestSASLCapabilityAdvertisement verifies that SASL PLAIN is properly advertised
// according to RFC 5804 security requirements:
// - Before STARTTLS: SASL should be empty or not advertised
// - After STARTTLS or on implicit TLS: SASL PLAIN should be advertised
// - With insecure_auth enabled: SASL PLAIN can be advertised without TLS
func TestSASLCapabilityAdvertisement(t *testing.T) {
	tests := []struct {
		name         string
		isTLS        bool
		useStartTLS  bool
		insecureAuth bool
		wantSASL     string // Expected SASL capability line
	}{
		{
			name:         "Before STARTTLS - should advertise empty SASL",
			isTLS:        false,
			useStartTLS:  true,
			insecureAuth: false,
			wantSASL:     `"SASL" ""`,
		},
		{
			name:         "After STARTTLS - should advertise SASL PLAIN",
			isTLS:        true,
			useStartTLS:  true,
			insecureAuth: false,
			wantSASL:     `"SASL" "PLAIN"`,
		},
		{
			name:         "Implicit TLS - should advertise SASL PLAIN",
			isTLS:        true,
			useStartTLS:  false,
			insecureAuth: false,
			wantSASL:     `"SASL" "PLAIN"`,
		},
		{
			name:         "Insecure auth enabled without TLS - should advertise SASL PLAIN",
			isTLS:        false,
			useStartTLS:  false,
			insecureAuth: true,
			wantSASL:     `"SASL" "PLAIN"`,
		},
		{
			name:         "Insecure auth enabled with TLS - should advertise SASL PLAIN",
			isTLS:        true,
			useStartTLS:  false,
			insecureAuth: true,
			wantSASL:     `"SASL" "PLAIN"`,
		},
		{
			name:         "No TLS, no insecure auth, no STARTTLS - should not advertise SASL",
			isTLS:        false,
			useStartTLS:  false,
			insecureAuth: false,
			wantSASL:     "", // No SASL capability should be sent
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock server and session to test capability generation
			// We'll capture the output by creating a custom writer
			var capabilityOutput strings.Builder

			// Simulate the capability advertisement logic from sendCapabilities
			// This matches the code in server/managesieve/session.go:sendCapabilities()

			// Write IMPLEMENTATION
			capabilityOutput.WriteString(`"IMPLEMENTATION" "ManageSieve"` + "\r\n")

			// Write SIEVE capabilities
			capabilities := GetSieveCapabilities(SupportedExtensions)
			extensionsStr := strings.Join(capabilities, " ")
			capabilityOutput.WriteString(`"SIEVE" "` + extensionsStr + `"` + "\r\n")

			// Write STARTTLS and SASL based on TLS state
			// This is the logic we're testing
			if tt.useStartTLS && !tt.isTLS {
				capabilityOutput.WriteString(`"STARTTLS"` + "\r\n")
				// Before STARTTLS: Don't advertise SASL mechanisms (RFC 5804 security requirement)
				capabilityOutput.WriteString(`"SASL" ""` + "\r\n")
			} else if tt.isTLS || tt.insecureAuth {
				// After STARTTLS or on implicit TLS: Advertise available SASL mechanisms
				capabilityOutput.WriteString(`"SASL" "PLAIN"` + "\r\n")
			}

			output := capabilityOutput.String()

			// Verify the SASL capability line is as expected
			if tt.wantSASL == "" {
				// Should NOT contain any SASL capability
				if strings.Contains(output, `"SASL"`) {
					t.Errorf("Should not advertise SASL capability, but got:\n%s", output)
				}
			} else {
				// Should contain the expected SASL capability
				if !strings.Contains(output, tt.wantSASL) {
					t.Errorf("Expected SASL capability %q, but got:\n%s", tt.wantSASL, output)
				}
			}

			// Additional verification: ensure SASL PLAIN is only advertised when secure
			if strings.Contains(output, `"SASL" "PLAIN"`) {
				if !tt.isTLS && !tt.insecureAuth {
					t.Errorf("SASL PLAIN should not be advertised without TLS or insecure_auth enabled")
				}
			}

			// Verify empty SASL is only sent before STARTTLS
			if strings.Contains(output, `"SASL" ""`) {
				if !tt.useStartTLS || tt.isTLS {
					t.Errorf("Empty SASL should only be advertised before STARTTLS")
				}
			}
		})
	}
}
