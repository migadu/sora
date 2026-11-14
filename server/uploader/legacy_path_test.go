package uploader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckLegacyStaging: a node upgraded with the default [uploader] path must not start
// while the previous default directory still holds staged bodies, which it would never
// upload. An explicit path, an absent or empty legacy directory, start normally.
func TestCheckLegacyStaging(t *testing.T) {
	root := t.TempDir()
	newDefault := filepath.Join(root, "spool", "uploads")
	legacy := filepath.Join(root, "tmp", "uploads")

	if err := CheckLegacyStaging(newDefault, newDefault, legacy); err != nil {
		t.Fatalf("legacy directory absent: %v", err)
	}

	// Account directories left behind without bodies strand nothing.
	if err := os.MkdirAll(filepath.Join(legacy, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyStaging(newDefault, newDefault, legacy); err != nil {
		t.Fatalf("legacy directory without bodies: %v", err)
	}

	body := filepath.Join(legacy, "42", strings.Repeat("a", 64))
	if err := os.WriteFile(body, []byte("staged"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CheckLegacyStaging(newDefault, newDefault, legacy)
	if err == nil {
		t.Fatal("default path with bodies staged under the legacy default: want an error, got nil")
	}
	if !strings.Contains(err.Error(), body) || !strings.Contains(err.Error(), `path = "`+legacy+`"`) {
		t.Errorf("error should name the stranded body and the setting that keeps it: %v", err)
	}

	// Trailing slash or other spelling of the default is the same directory.
	if err := CheckLegacyStaging(newDefault+"/", newDefault, legacy); err == nil {
		t.Error("default path spelled with a trailing slash: want an error, got nil")
	}

	// An operator who configured a path chose where bodies live; nothing is inferred.
	if err := CheckLegacyStaging(filepath.Join(root, "elsewhere"), newDefault, legacy); err != nil {
		t.Errorf("explicit non-default path: %v", err)
	}
	if err := CheckLegacyStaging(legacy, newDefault, legacy); err != nil {
		t.Errorf("path set to the legacy directory itself: %v", err)
	}
}
