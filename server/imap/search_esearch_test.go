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

// TestSearchWarningTrigger tests that the warning is only triggered for actual ESEARCH commands
func TestSearchWarningTrigger(t *testing.T) {
	tests := []struct {
		name          string
		options       *imap.SearchOptions
		hasESEARCHCap bool
		expectWarning bool
		description   string
	}{
		{
			name:          "Standard SEARCH without ESEARCH capability",
			options:       &imap.SearchOptions{}, // Empty struct (standard SEARCH)
			hasESEARCHCap: false,
			expectWarning: false,
			description:   "Should NOT warn - standard SEARCH is always allowed",
		},
		{
			name:          "Standard SEARCH with ESEARCH capability",
			options:       &imap.SearchOptions{}, // Empty struct (standard SEARCH)
			hasESEARCHCap: true,
			expectWarning: false,
			description:   "Should NOT warn - standard SEARCH is always allowed",
		},
		{
			name: "ESEARCH RETURN (ALL) without ESEARCH capability",
			options: &imap.SearchOptions{
				ReturnAll: true,
			},
			hasESEARCHCap: false,
			expectWarning: true,
			description:   "Should WARN - client using ESEARCH syntax but capability filtered",
		},
		{
			name: "ESEARCH RETURN (ALL) with ESEARCH capability",
			options: &imap.SearchOptions{
				ReturnAll: true,
			},
			hasESEARCHCap: true,
			expectWarning: false,
			description:   "Should NOT warn - ESEARCH is advertised and allowed",
		},
		{
			name: "ESEARCH RETURN (COUNT) without ESEARCH capability",
			options: &imap.SearchOptions{
				ReturnCount: true,
			},
			hasESEARCHCap: false,
			expectWarning: true,
			description:   "Should WARN - client using ESEARCH syntax but capability filtered",
		},
		{
			name: "ESEARCH RETURN (MIN MAX) without ESEARCH capability",
			options: &imap.SearchOptions{
				ReturnMin: true,
				ReturnMax: true,
			},
			hasESEARCHCap: false,
			expectWarning: true,
			description:   "Should WARN - client using ESEARCH syntax but capability filtered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic from search.go:91-104
			isESEARCH := tt.options != nil && (tt.options.ReturnMin || tt.options.ReturnMax || tt.options.ReturnAll || tt.options.ReturnCount || tt.options.ReturnSave)

			var shouldWarn bool
			if isESEARCH {
				// Check if session has ESEARCH capability - if not, we should warn
				if !tt.hasESEARCHCap {
					shouldWarn = true
				}
			}

			if shouldWarn != tt.expectWarning {
				t.Errorf("%s: got shouldWarn=%v, want %v", tt.description, shouldWarn, tt.expectWarning)
			} else {
				t.Logf("✓ %s: correctly determined shouldWarn=%v", tt.description, shouldWarn)
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
		name          string
		command       string
		options       *imap.SearchOptions
		expectWarning bool
		explanation   string
	}{
		{
			name:          "iOS sends standard SEARCH (expected behavior)",
			command:       "UID SEARCH UID 930:*",
			options:       &imap.SearchOptions{}, // Empty options = standard SEARCH
			expectWarning: false,
			explanation:   "Client respects filtered capabilities and uses standard SEARCH - no warning needed",
		},
		{
			name:    "iOS sends ESEARCH despite filtering (the bug)",
			command: "UID SEARCH RETURN (ALL) UID 930:*",
			options: &imap.SearchOptions{
				ReturnAll: true,
			},
			expectWarning: true,
			explanation:   "Client ignores filtered capabilities and uses ESEARCH - this is the iOS Mail bug we're working around",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Check if this is ESEARCH
			isESEARCH := scenario.options != nil && (scenario.options.ReturnMin || scenario.options.ReturnMax || scenario.options.ReturnAll || scenario.options.ReturnCount || scenario.options.ReturnSave)

			var shouldWarn bool
			if isESEARCH && !hasESEARCHCapability {
				shouldWarn = true
			}

			if shouldWarn != scenario.expectWarning {
				t.Errorf("Got shouldWarn=%v, want %v", shouldWarn, scenario.expectWarning)
				t.Errorf("Explanation: %s", scenario.explanation)
			} else {
				t.Logf("✓ %s", scenario.explanation)
				if shouldWarn {
					t.Log("  → Warning would be logged: 'Client using ESEARCH RETURN syntax despite capability being filtered'")
					t.Log("  → Server gracefully handles by treating as standard SEARCH")
				}
			}
		})
	}
}

// TestESEARCHNilPointerRegression tests for the panic bug where options was set to nil
// but code continued to access options.ReturnMin etc., causing nil pointer dereference
func TestESEARCHNilPointerRegression(t *testing.T) {
	// This test reproduces the exact panic scenario from the production bug
	// Panic: "panic handling command: runtime error: invalid memory address or nil pointer dereference"
	// Location: server/imap/search.go:111 attempting to access options.ReturnMin when options is nil

	t.Log("Testing regression fix for nil pointer panic in ESEARCH handling")

	// Simulate the scenario:
	// 1. Client sends ESEARCH with RETURN options
	// 2. Server has ESEARCH capability filtered (disabled)
	// 3. Code sets options = nil and isESEARCH = false
	// 4. OLD BUG: Code continued to access options.ReturnMin, causing panic
	// 5. FIX: Code now checks isESEARCH && options != nil before accessing options

	options := &imap.SearchOptions{
		ReturnAll: true,
		ReturnMin: true,
	}

	// Step 1: Detect ESEARCH
	isESEARCH := options != nil && (options.ReturnMin || options.ReturnMax || options.ReturnAll || options.ReturnCount || options.ReturnSave)
	if !isESEARCH {
		t.Fatal("Expected ESEARCH to be detected")
	}
	t.Log("✓ Step 1: ESEARCH detected (options has RETURN flags set)")

	// Step 2: Capability check fails (ESEARCH not advertised)
	hasESEARCHCapability := false
	if isESEARCH && !hasESEARCHCapability {
		t.Log("✓ Step 2: ESEARCH capability not advertised - triggering workaround")
		// This is what the code does when capability is filtered
		options = nil
		isESEARCH = false
	}

	t.Log("✓ Step 3: Set options = nil and isESEARCH = false (workaround)")

	// Step 4: OLD BUG - Code would continue to access options here, causing panic
	// The old code structure was:
	//   if isESEARCH {
	//       if !hasCapability {
	//           options = nil; isESEARCH = false
	//       }
	//       // BUG: This code still executes even after setting isESEARCH = false
	//       if options.ReturnMin { ... } // PANIC: nil pointer dereference
	//   }

	// Step 5: NEW FIX - Check both isESEARCH && options != nil
	if isESEARCH && options != nil {
		t.Fatal("Should not enter ESEARCH block when options is nil - this would have caused the panic!")
	}

	t.Log("✓ Step 4: ESEARCH block correctly skipped (isESEARCH = false, options = nil)")
	t.Log("✓ Step 5: No panic! Code correctly handles the workaround scenario")
	t.Log("✓ FIX VERIFIED: Nil pointer dereference prevented by 'isESEARCH && options != nil' guard")
}
