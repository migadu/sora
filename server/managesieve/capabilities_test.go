package managesieve

import (
	"strings"
	"testing"
)

func TestBuiltinSieveCapabilities(t *testing.T) {
	// Verify builtin capabilities are defined
	if len(BuiltinSieveCapabilities) == 0 {
		t.Fatal("BuiltinSieveCapabilities should not be empty")
	}

	// Verify essential RFC 5228 capabilities are present
	essentials := []string{"fileinto", "reject", "envelope", "variables"}
	for _, essential := range essentials {
		found := false
		for _, cap := range BuiltinSieveCapabilities {
			if cap == essential {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential capability %q not found in BuiltinSieveCapabilities", essential)
		}
	}
}

func TestGetSieveCapabilities(t *testing.T) {
	tests := []struct {
		name                 string
		additionalExtensions []string
		wantContains         []string
		wantCount            int
	}{
		{
			name:                 "No additional extensions",
			additionalExtensions: nil,
			wantContains:         []string{"fileinto", "reject", "envelope"},
			wantCount:            len(BuiltinSieveCapabilities),
		},
		{
			name:                 "With additional extensions",
			additionalExtensions: []string{"vacation", "regex"},
			wantContains:         []string{"fileinto", "vacation", "regex"},
			wantCount:            len(BuiltinSieveCapabilities) + 2,
		},
		{
			name:                 "Empty additional extensions",
			additionalExtensions: []string{},
			wantContains:         []string{"fileinto", "reject"},
			wantCount:            len(BuiltinSieveCapabilities),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetSieveCapabilities(tt.additionalExtensions)

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
	// Test with duplicates in additional extensions
	additional := []string{"vacation", "fileinto", "regex"} // fileinto is already in builtin
	caps := GetSieveCapabilities(additional)

	// Count occurrences
	counts := make(map[string]int)
	for _, cap := range caps {
		counts[cap]++
	}

	// After deduplication, no capability should appear more than once
	for cap, count := range counts {
		if count > 1 {
			t.Errorf("Capability %q appears %d times (should be deduplicated)", cap, count)
		}
	}
}

func TestValidateExtensions(t *testing.T) {
	tests := []struct {
		name       string
		extensions []string
		wantErr    bool
	}{
		{
			name:       "Valid additional extensions",
			extensions: []string{"vacation", "regex"},
			wantErr:    false,
		},
		{
			name:       "Valid builtin extensions",
			extensions: []string{"fileinto", "reject"},
			wantErr:    false,
		},
		{
			name:       "Mixed valid extensions",
			extensions: []string{"vacation", "fileinto", "regex"},
			wantErr:    false,
		},
		{
			name:       "Invalid extension",
			extensions: []string{"invalid_extension"},
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
	additional := []string{"vacation", "regex"}
	caps := GetSieveCapabilities(additional)

	capsStr := strings.Join(caps, " ")

	if capsStr == "" {
		t.Error("Capabilities string should not be empty")
	}

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
}
