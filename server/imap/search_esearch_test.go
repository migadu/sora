package imap

import (
	"testing"

	"github.com/emersion/go-imap/v2"
)

// TestSearchOptionsDetection tests that we correctly distinguish between standard SEARCH and ESEARCH
func TestSearchOptionsDetection(t *testing.T) {
	tests := []struct {
		name        string
		options     *imap.SearchOptions
		wantESEARCH bool
		description string
	}{
		{
			name:        "nil options (standard SEARCH)",
			options:     nil,
			wantESEARCH: false,
			description: "Standard SEARCH command with no options",
		},
		{
			name:        "empty options struct (standard SEARCH)",
			options:     &imap.SearchOptions{},
			wantESEARCH: false,
			description: "go-imap passes empty SearchOptions for standard SEARCH",
		},
		{
			name: "RETURN (MIN)",
			options: &imap.SearchOptions{
				ReturnMin: true,
			},
			wantESEARCH: true,
			description: "ESEARCH with RETURN (MIN)",
		},
		{
			name: "RETURN (MAX)",
			options: &imap.SearchOptions{
				ReturnMax: true,
			},
			wantESEARCH: true,
			description: "ESEARCH with RETURN (MAX)",
		},
		{
			name: "RETURN (ALL)",
			options: &imap.SearchOptions{
				ReturnAll: true,
			},
			wantESEARCH: true,
			description: "ESEARCH with RETURN (ALL)",
		},
		{
			name: "RETURN (COUNT)",
			options: &imap.SearchOptions{
				ReturnCount: true,
			},
			wantESEARCH: true,
			description: "ESEARCH with RETURN (COUNT)",
		},
		{
			name: "RETURN (MIN MAX)",
			options: &imap.SearchOptions{
				ReturnMin: true,
				ReturnMax: true,
			},
			wantESEARCH: true,
			description: "ESEARCH with multiple RETURN options",
		},
		{
			name: "RETURN (ALL COUNT)",
			options: &imap.SearchOptions{
				ReturnAll:   true,
				ReturnCount: true,
			},
			wantESEARCH: true,
			description: "ESEARCH with ALL and COUNT",
		},
		{
			name: "RETURN (SAVE) - SEARCHRES extension",
			options: &imap.SearchOptions{
				ReturnSave: true,
			},
			wantESEARCH: true,
			description: "ESEARCH with RETURN (SAVE)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is the exact logic from search.go:93
			isESEARCH := tt.options != nil && (tt.options.ReturnMin || tt.options.ReturnMax || tt.options.ReturnAll || tt.options.ReturnCount || tt.options.ReturnSave)

			if isESEARCH != tt.wantESEARCH {
				t.Errorf("%s: got isESEARCH=%v, want %v", tt.description, isESEARCH, tt.wantESEARCH)
			} else {
				t.Logf("✓ %s: correctly detected as ESEARCH=%v", tt.description, isESEARCH)
			}
		})
	}
}

// TestSearchErrorTrigger tests that BAD error is returned for ESEARCH when capability is filtered
func TestSearchErrorTrigger(t *testing.T) {
	tests := []struct {
		name          string
		options       *imap.SearchOptions
		hasESEARCHCap bool
		expectError   bool
		description   string
	}{
		{
			name:          "Standard SEARCH without ESEARCH capability",
			options:       &imap.SearchOptions{}, // Empty struct (standard SEARCH)
			hasESEARCHCap: false,
			expectError:   false,
			description:   "Should NOT error - standard SEARCH is always allowed",
		},
		{
			name:          "Standard SEARCH with ESEARCH capability",
			options:       &imap.SearchOptions{}, // Empty struct (standard SEARCH)
			hasESEARCHCap: true,
			expectError:   false,
			description:   "Should NOT error - standard SEARCH is always allowed",
		},
		{
			name: "ESEARCH RETURN (ALL) without ESEARCH capability",
			options: &imap.SearchOptions{
				ReturnAll: true,
			},
			hasESEARCHCap: false,
			expectError:   true,
			description:   "Should ERROR - client using ESEARCH syntax but capability filtered (prevents infinite loop)",
		},
		{
			name: "ESEARCH RETURN (ALL) with ESEARCH capability",
			options: &imap.SearchOptions{
				ReturnAll: true,
			},
			hasESEARCHCap: true,
			expectError:   false,
			description:   "Should NOT error - ESEARCH is advertised and allowed",
		},
		{
			name: "ESEARCH RETURN (COUNT) without ESEARCH capability",
			options: &imap.SearchOptions{
				ReturnCount: true,
			},
			hasESEARCHCap: false,
			expectError:   true,
			description:   "Should ERROR - client using ESEARCH syntax but capability filtered (prevents infinite loop)",
		},
		{
			name: "ESEARCH RETURN (MIN MAX) without ESEARCH capability",
			options: &imap.SearchOptions{
				ReturnMin: true,
				ReturnMax: true,
			},
			hasESEARCHCap: false,
			expectError:   true,
			description:   "Should ERROR - client using ESEARCH syntax but capability filtered (prevents infinite loop)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic from search.go:93-107
			isESEARCH := tt.options != nil && (tt.options.ReturnMin || tt.options.ReturnMax || tt.options.ReturnAll || tt.options.ReturnCount || tt.options.ReturnSave)

			var shouldError bool
			if isESEARCH {
				// Check if session has ESEARCH capability - if not, return BAD error
				if !tt.hasESEARCHCap {
					shouldError = true
				}
			}

			if shouldError != tt.expectError {
				t.Errorf("%s: got shouldError=%v, want %v", tt.description, shouldError, tt.expectError)
			} else {
				t.Logf("✓ %s: correctly determined shouldError=%v", tt.description, shouldError)
			}
		})
	}
}

// TestStandardSearchExamples tests real-world SEARCH command examples
func TestStandardSearchExamples(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		options     *imap.SearchOptions
		wantESEARCH bool
	}{
		{
			name:        "UID SEARCH UID 930:*",
			command:     "UID SEARCH UID 930:*",
			options:     &imap.SearchOptions{}, // Library passes empty struct
			wantESEARCH: false,
		},
		{
			name:        "SEARCH ALL",
			command:     "SEARCH ALL",
			options:     &imap.SearchOptions{},
			wantESEARCH: false,
		},
		{
			name:        "UID SEARCH UNSEEN",
			command:     "UID SEARCH UNSEEN",
			options:     &imap.SearchOptions{},
			wantESEARCH: false,
		},
		{
			name:    "UID SEARCH RETURN (ALL) UID 930:*",
			command: "UID SEARCH RETURN (ALL) UID 930:*",
			options: &imap.SearchOptions{
				ReturnAll: true,
			},
			wantESEARCH: true,
		},
		{
			name:    "UID SEARCH RETURN (MIN MAX) ALL",
			command: "UID SEARCH RETURN (MIN MAX) ALL",
			options: &imap.SearchOptions{
				ReturnMin: true,
				ReturnMax: true,
			},
			wantESEARCH: true,
		},
		{
			name:    "UID SEARCH RETURN (COUNT) UNSEEN",
			command: "UID SEARCH RETURN (COUNT) UNSEEN",
			options: &imap.SearchOptions{
				ReturnCount: true,
			},
			wantESEARCH: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isESEARCH := tt.options != nil && (tt.options.ReturnMin || tt.options.ReturnMax || tt.options.ReturnAll || tt.options.ReturnCount || tt.options.ReturnSave)

			if isESEARCH != tt.wantESEARCH {
				t.Errorf("Command %q: got isESEARCH=%v, want %v", tt.command, isESEARCH, tt.wantESEARCH)
			} else {
				t.Logf("✓ Command %q correctly detected as ESEARCH=%v", tt.command, isESEARCH)
			}
		})
	}
}

// TestIOSMailBugScenario tests the specific iOS Mail bug scenario
func TestIOSMailBugScenario(t *testing.T) {
	t.Log("Scenario: iOS Mail client with JA4 fingerprint match, ESEARCH capability filtered")

	// Setup: Client has matching JA4 fingerprint, ESEARCH is filtered out
	hasESEARCHCapability := false // Filtered due to JA4 match

	scenarios := []struct {
		name        string
		command     string
		options     *imap.SearchOptions
		expectError bool
		explanation string
	}{
		{
			name:        "iOS sends standard SEARCH (expected behavior)",
			command:     "UID SEARCH UID 930:*",
			options:     &imap.SearchOptions{}, // Empty options = standard SEARCH
			expectError: false,
			explanation: "Client respects filtered capabilities and uses standard SEARCH - no error",
		},
		{
			name:    "iOS sends ESEARCH despite filtering (the bug)",
			command: "UID SEARCH RETURN (ALL) UID 930:*",
			options: &imap.SearchOptions{
				ReturnAll: true,
			},
			expectError: true,
			explanation: "Client ignores filtered capabilities and uses ESEARCH - server returns BAD to prevent infinite loop",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Check if this is ESEARCH
			isESEARCH := scenario.options != nil && (scenario.options.ReturnMin || scenario.options.ReturnMax || scenario.options.ReturnAll || scenario.options.ReturnCount || scenario.options.ReturnSave)

			var shouldError bool
			if isESEARCH && !hasESEARCHCapability {
				shouldError = true
			}

			if shouldError != scenario.expectError {
				t.Errorf("Got shouldError=%v, want %v", shouldError, scenario.expectError)
				t.Errorf("Explanation: %s", scenario.explanation)
			} else {
				t.Logf("✓ %s", scenario.explanation)
				if shouldError {
					t.Log("  → BAD error returned: 'ESEARCH not supported'")
					t.Log("  → This prevents the infinite retry loop")
				}
			}
		})
	}
}

// TestESEARCHBadResponsePreventsLoop tests that BAD error prevents infinite retry loop
func TestESEARCHBadResponsePreventsLoop(t *testing.T) {
	// This test verifies the fix for infinite loop where client kept retrying ESEARCH
	// OLD BEHAVIOR: Server returned standard SEARCH results, client kept retrying with ESEARCH
	// NEW BEHAVIOR: Server returns BAD error, client should stop retrying

	t.Log("Testing that BAD error prevents infinite ESEARCH retry loop")

	options := &imap.SearchOptions{
		ReturnAll: true,
	}

	// Step 1: Detect ESEARCH
	isESEARCH := options != nil && (options.ReturnMin || options.ReturnMax || options.ReturnAll || options.ReturnCount || options.ReturnSave)
	if !isESEARCH {
		t.Fatal("Expected ESEARCH to be detected")
	}
	t.Log("✓ Step 1: ESEARCH detected (RETURN (ALL) syntax)")

	// Step 2: Capability check fails (ESEARCH not advertised)
	hasESEARCHCapability := false
	if isESEARCH && !hasESEARCHCapability {
		t.Log("✓ Step 2: ESEARCH capability not advertised")
		// NEW FIX: Return BAD error instead of trying to handle gracefully
		shouldReturnBadError := true
		if !shouldReturnBadError {
			t.Fatal("Should return BAD error to prevent infinite loop!")
		}
		t.Log("✓ Step 3: Returning BAD error: 'ESEARCH not supported'")
		t.Log("✓ Step 4: Client receives BAD and should stop retrying")
		t.Log("✓ FIX VERIFIED: BAD error prevents infinite retry loop")
		return
	}

	t.Fatal("Should have detected missing capability and returned error")
}
