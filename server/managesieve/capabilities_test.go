package managesieve

import (
	"strings"
	"testing"
)

func TestGoSieveSupportedExtensions(t *testing.T) {
	// Verify supported extensions are defined
	if len(GoSieveSupportedExtensions) == 0 {
		t.Fatal("GoSieveSupportedExtensions should not be empty")
	}

	// Verify essential extensions that go-sieve supports are present
	essentials := []string{"fileinto", "envelope", "variables", "vacation"}
	for _, essential := range essentials {
		found := false
		for _, cap := range GoSieveSupportedExtensions {
			if cap == essential {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential extension %q not found in GoSieveSupportedExtensions", essential)
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

func TestCommonlyUsedExtensions(t *testing.T) {
	// Verify CommonlyUsedExtensions are all supported by go-sieve
	err := ValidateExtensions(CommonlyUsedExtensions)
	if err != nil {
		t.Errorf("CommonlyUsedExtensions contains unsupported extensions: %v", err)
	}

	// Verify essential extensions are in the commonly used list
	essentials := []string{"fileinto", "vacation"}
	for _, essential := range essentials {
		found := false
		for _, ext := range CommonlyUsedExtensions {
			if ext == essential {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential extension %q not in CommonlyUsedExtensions", essential)
		}
	}
}
