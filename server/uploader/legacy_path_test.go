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

// TestCheckLegacyStagingFollowsSymlink: an administrator who kept the /tmp default on
// persistent storage did it with a symlink (/tmp/sora/uploads -> /data/uploads). The
// uploader followed it, so the bodies behind it are just as stranded by the new default.
func TestCheckLegacyStagingFollowsSymlink(t *testing.T) {
	root := t.TempDir()
	newDefault := filepath.Join(root, "spool", "uploads")
	target := filepath.Join(root, "data", "uploads")
	legacy := filepath.Join(root, "tmp", "uploads")

	if err := os.MkdirAll(filepath.Join(target, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "42", strings.Repeat("a", 64)), []byte("staged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, legacy); err != nil {
		t.Fatal(err)
	}

	if err := CheckLegacyStaging(newDefault, newDefault, legacy); err == nil {
		t.Fatal("legacy directory is a symlink to staged bodies: want an error, got nil")
	}

	// A dangling symlink holds nothing.
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyStaging(newDefault, newDefault, legacy); err != nil {
		t.Errorf("dangling legacy symlink: %v", err)
	}
}

func TestCheckLegacyStagingFollowsNestedSymlink(t *testing.T) {
	for _, directory := range []bool{true, false} {
		name := "body file"
		if directory {
			name = "account directory"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			legacy, persistent := filepath.Join(root, "old"), filepath.Join(root, "persistent")
			if err := os.MkdirAll(persistent, 0o755); err != nil {
				t.Fatal(err)
			}
			body := filepath.Join(persistent, strings.Repeat("a", 64))
			if err := os.WriteFile(body, []byte("staged"), 0o600); err != nil {
				t.Fatal(err)
			}
			link, target := filepath.Join(legacy, "42"), persistent
			if !directory {
				link, target = filepath.Join(link, strings.Repeat("a", 64)), body
			}
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			newDefault := filepath.Join(root, "new")
			if err := CheckLegacyStaging(newDefault, newDefault, legacy); err == nil {
				t.Fatal("legacy spool reaches a staged body through a nested symlink; want refusal")
			}
		})
	}
}

func TestCheckLegacyStagingSymlinkCycleWithoutBodies(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "old")
	account := filepath.Join(legacy, "42")
	if err := os.MkdirAll(account, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(legacy, filepath.Join(account, "cycle")); err != nil {
		t.Fatal(err)
	}
	newDefault := filepath.Join(root, "new")
	if err := CheckLegacyStaging(newDefault, newDefault, legacy); err != nil {
		t.Errorf("empty legacy spool with a symlink cycle: %v", err)
	}
}
