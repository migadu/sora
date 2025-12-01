package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadConfigFromFile_UnknownKeys tests that unknown keys produce warnings but don't fail
func TestLoadConfigFromFile_UnknownKeys(t *testing.T) {
	// Create temporary config file with unknown keys
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_unknown.toml")

	content := `
[database]
[database.write]
hosts = ["localhost:5432"]
user = "postgres"
name = "sora_mail_db"

# Unknown keys
unknown_key = "should warn"
typo_setting = 123

[servers.imap]
start = true
addr = ":1143"
another_unknown = "value"
`

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := &Config{}
	err := LoadConfigFromFile(configPath, cfg)

	// Should NOT return error - unknown keys are just warnings
	if err != nil {
		t.Errorf("LoadConfigFromFile returned unexpected error: %v", err)
	}

	// Verify valid config was loaded
	if cfg.Database.Write == nil {
		t.Error("Expected database.write to be loaded")
	}
	if cfg.Database.Write.User != "postgres" {
		t.Errorf("Expected user=postgres, got %s", cfg.Database.Write.User)
	}
}

// TestRemoveDuplicateKeys_SimpleSection tests duplicate detection in simple sections
func TestRemoveDuplicateKeys_SimpleSection(t *testing.T) {
	content := `
[database]
debug = true
debug = false

[database.write]
user = "postgres"
user = "admin"
`

	cleaned, err := removeDuplicateKeysFromTOML(content)
	if err != nil {
		t.Fatalf("removeDuplicateKeysFromTOML failed: %v", err)
	}

	// Should comment out the duplicate
	if !strings.Contains(cleaned, "# DUPLICATE IGNORED: debug = false") {
		t.Error("Expected second 'debug' to be commented out")
	}

	if !strings.Contains(cleaned, "# DUPLICATE IGNORED: user = \"admin\"") {
		t.Error("Expected second 'user' to be commented out")
	}

	// First occurrence should remain
	lines := strings.Split(cleaned, "\n")
	hasFirstDebug := false
	hasFirstUser := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "debug = true" {
			hasFirstDebug = true
		}
		if strings.Contains(line, "user = \"postgres\"") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			hasFirstUser = true
		}
	}

	if !hasFirstDebug {
		t.Error("Expected first 'debug = true' to be preserved")
	}
	if !hasFirstUser {
		t.Error("Expected first 'user = \"postgres\"' to be preserved")
	}
}

// TestRemoveDuplicateKeys_NestedSections tests duplicate detection in nested sections
func TestRemoveDuplicateKeys_NestedSections(t *testing.T) {
	content := `
[database.write]
hosts = ["db1:5432"]

[database.read]
hosts = ["db2:5432"]

[database.write]
hosts = ["db3:5432"]
`

	cleaned, err := removeDuplicateKeysFromTOML(content)
	if err != nil {
		t.Fatalf("removeDuplicateKeysFromTOML failed: %v", err)
	}

	// The duplicate section [database.write] should be preserved (sections can repeat)
	// But duplicate keys within sections should be caught
	lines := strings.Split(cleaned, "\n")
	writeCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "[database.write]" {
			writeCount++
		}
	}

	// Both section headers should be present (TOML allows repeated sections)
	if writeCount != 2 {
		t.Errorf("Expected 2 [database.write] sections, got %d", writeCount)
	}
}

// TestRemoveDuplicateKeys_ArrayTables tests array table syntax [[table]]
func TestRemoveDuplicateKeys_ArrayTables(t *testing.T) {
	content := `
[[servers.proxy]]
name = "proxy1"
addr = ":8080"

[[servers.proxy]]
name = "proxy2"
addr = ":8081"

[database]
debug = true
debug = false
`

	cleaned, err := removeDuplicateKeysFromTOML(content)
	if err != nil {
		t.Fatalf("removeDuplicateKeysFromTOML failed: %v", err)
	}

	// Array tables should be preserved (they're meant to be repeated)
	lines := strings.Split(cleaned, "\n")
	arrayTableCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "[[servers.proxy]]" {
			arrayTableCount++
		}
	}

	if arrayTableCount != 2 {
		t.Errorf("Expected 2 [[servers.proxy]] sections, got %d", arrayTableCount)
	}

	// Regular duplicate should still be caught
	if !strings.Contains(cleaned, "# DUPLICATE IGNORED: debug = false") {
		t.Error("Expected duplicate 'debug' in regular section to be commented out")
	}
}

// TestRemoveDuplicateKeys_TopLevelKeys tests keys without a section
func TestRemoveDuplicateKeys_TopLevelKeys(t *testing.T) {
	content := `
# Top-level keys
version = "1.0"
version = "2.0"

[database]
debug = true
`

	cleaned, err := removeDuplicateKeysFromTOML(content)
	if err != nil {
		t.Fatalf("removeDuplicateKeysFromTOML failed: %v", err)
	}

	// Duplicate top-level key should be commented out
	if !strings.Contains(cleaned, "# DUPLICATE IGNORED: version = \"2.0\"") {
		t.Error("Expected second 'version' to be commented out")
	}

	// First occurrence should remain
	if !strings.Contains(cleaned, "version = \"1.0\"") {
		t.Error("Expected first 'version = \"1.0\"' to be preserved")
	}
}

// TestEnhanceConfigError_BooleanVariants tests error hints for various boolean typos
func TestEnhanceConfigError_BooleanVariants(t *testing.T) {
	tests := []struct {
		name        string
		errorMsg    string
		shouldMatch bool
	}{
		{
			name:        "f instead of false",
			errorMsg:    `toml: line 5: expected value but found "f" instead`,
			shouldMatch: true,
		},
		{
			name:        "t instead of true",
			errorMsg:    `toml: line 5: expected value but found "t" instead`,
			shouldMatch: true,
		},
		{
			name:        "regular syntax error",
			errorMsg:    `toml: line 5: expected value but found "[" instead`,
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock error
			mockErr := &mockError{msg: tt.errorMsg}
			enhanced := enhanceConfigError(mockErr)

			enhancedStr := enhanced.Error()
			hasBooleanHint := strings.Contains(enhancedStr, "Invalid boolean value")

			if tt.shouldMatch && !hasBooleanHint {
				t.Errorf("Expected boolean hint for error: %s", tt.errorMsg)
			}
			if !tt.shouldMatch && hasBooleanHint {
				t.Errorf("Did not expect boolean hint for error: %s", tt.errorMsg)
			}

			// All enhanced errors should contain the original error
			if !strings.Contains(enhancedStr, tt.errorMsg) {
				t.Error("Enhanced error should contain original error message")
			}
		})
	}
}

// TestLoadConfigFromFile_BooleanTyos tests that boolean typos fail with helpful error
func TestLoadConfigFromFile_BooleanTyos(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_bool.toml")

	content := `
[database]
[database.write]
hosts = ["localhost:5432"]
debug = f
`

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := &Config{}
	err := LoadConfigFromFile(configPath, cfg)

	// Should return error with helpful hint
	if err == nil {
		t.Fatal("Expected error for 'f' instead of 'false'")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "Invalid boolean value") {
		t.Errorf("Expected boolean hint in error, got: %v", err)
	}

	if !strings.Contains(errStr, "Using 'f' instead of 'false'") {
		t.Errorf("Expected specific hint about 'f', got: %v", err)
	}
}

// TestLoadConfigFromFile_DuplicateKeys tests that duplicate keys are handled gracefully
func TestLoadConfigFromFile_DuplicateKeys(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_dup.toml")

	content := `
[database]
[database.write]
hosts = ["localhost:5432"]
user = "postgres"
user = "admin"
`

	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := &Config{}
	err := LoadConfigFromFile(configPath, cfg)

	// Should NOT return error - duplicates are handled
	if err != nil {
		t.Errorf("LoadConfigFromFile should handle duplicates gracefully, got error: %v", err)
	}

	// First value should win
	if cfg.Database.Write != nil && cfg.Database.Write.User != "postgres" {
		t.Errorf("Expected first value 'postgres', got: %s", cfg.Database.Write.User)
	}
}

// TestRemoveDuplicateKeys_MultipleServers tests that multiple [[server]] blocks don't trigger false duplicates
func TestRemoveDuplicateKeys_MultipleServers(t *testing.T) {
	content := `
[[server]]
type = "imap_proxy"
name = "imap-main-ip4"
addr = "0.0.0.0:993"
max_connections = 10000

[server.auth_rate_limit]
enabled = false
max_attempts_per_ip = 10

[server.remote_lookup]
enabled = true
url = "https://api.example.com/lookup/$email"

[[server]]
type = "imap_proxy"
name = "imap-main-ip6"
addr = "[::]:993"
max_connections = 10000

[server.auth_rate_limit]
enabled = false
max_attempts_per_ip = 10

[server.remote_lookup]
enabled = true
url = "https://api.example.com/lookup/$email"
`

	cleaned, err := removeDuplicateKeysFromTOML(content)
	if err != nil {
		t.Fatalf("removeDuplicateKeysFromTOML failed: %v", err)
	}

	// Count how many times keys appear in cleaned output
	// None should be marked as duplicates since each [[server]] is a new array element
	duplicateCount := strings.Count(cleaned, "# DUPLICATE IGNORED:")
	if duplicateCount > 0 {
		t.Errorf("Expected no false duplicates in multiple [[server]] blocks, but found %d duplicates:\n%s",
			duplicateCount, cleaned)
	}

	// Verify both server blocks are preserved
	serverCount := strings.Count(cleaned, "[[server]]")
	if serverCount != 2 {
		t.Errorf("Expected 2 [[server]] blocks, got %d", serverCount)
	}

	// Verify all sections are present and not commented out
	if !strings.Contains(cleaned, "type = \"imap_proxy\"") {
		t.Error("Expected 'type' key to be preserved")
	}
	if !strings.Contains(cleaned, "[server.auth_rate_limit]") {
		t.Error("Expected [server.auth_rate_limit] sections to be preserved")
	}
	if !strings.Contains(cleaned, "[server.remote_lookup]") {
		t.Error("Expected [server.remote_lookup] sections to be preserved")
	}
}

// mockError is a simple error type for testing
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
