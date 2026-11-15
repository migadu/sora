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

	if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err != nil {
		t.Fatalf("legacy directory absent: %v", err)
	}

	// Account directories left behind without bodies strand nothing.
	if err := os.MkdirAll(filepath.Join(legacy, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err != nil {
		t.Fatalf("legacy directory without bodies: %v", err)
	}

	body := filepath.Join(legacy, "42", strings.Repeat("a", 64))
	if err := os.WriteFile(body, []byte("staged"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid())
	if err == nil {
		t.Fatal("default path with bodies staged under the legacy default: want an error, got nil")
	}
	if !strings.Contains(err.Error(), body) || !strings.Contains(err.Error(), `path = "`+legacy+`"`) {
		t.Errorf("error should name the stranded body and the setting that keeps it: %v", err)
	}

	// Trailing slash or other spelling of the default is the same directory.
	if err := CheckLegacyStaging(newDefault+"/", newDefault, legacy, os.Geteuid()); err == nil {
		t.Error("default path spelled with a trailing slash: want an error, got nil")
	}

	// An operator who configured a path chose where bodies live; nothing is inferred.
	if err := CheckLegacyStaging(filepath.Join(root, "elsewhere"), newDefault, legacy, os.Geteuid()); err != nil {
		t.Errorf("explicit non-default path: %v", err)
	}
	if err := CheckLegacyStaging(legacy, newDefault, legacy, os.Geteuid()); err != nil {
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

	if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err == nil {
		t.Fatal("legacy directory is a symlink to staged bodies: want an error, got nil")
	}

	// A dangling symlink holds nothing.
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err != nil {
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
			if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err == nil {
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
	if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err != nil {
		t.Errorf("empty legacy spool with a symlink cycle: %v", err)
	}
}

func TestCheckLegacyStagingSharedSymlinkTarget(t *testing.T) {
	hash := strings.Repeat("a", 64)

	t.Run("legacy symlinked to active default", func(t *testing.T) {
		root := t.TempDir()
		newDefault := filepath.Join(root, "spool", "uploads")
		legacy := filepath.Join(root, "tmp", "uploads")
		if err := os.MkdirAll(filepath.Join(newDefault, "42"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(newDefault, "42", hash), []byte("live"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(newDefault, legacy); err != nil {
			t.Fatal(err)
		}
		if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err != nil {
			t.Fatalf("legacy compatibility symlink to active spool refused startup: %v", err)
		}
	})

	t.Run("active default symlinked to legacy or shared persistent target", func(t *testing.T) {
		root := t.TempDir()
		persistent := filepath.Join(root, "data", "uploads")
		newDefault := filepath.Join(root, "spool", "uploads")
		legacy := filepath.Join(root, "tmp", "uploads")
		if err := os.MkdirAll(filepath.Join(persistent, "42"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(persistent, "42", hash), []byte("live"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, link := range []string{newDefault, legacy} {
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(persistent, link); err != nil {
				t.Fatal(err)
			}
		}
		if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err != nil {
			t.Fatalf("active and legacy spool sharing symlink target refused startup: %v", err)
		}
	})

	t.Run("nested account symlinks", func(t *testing.T) {
		root := t.TempDir()
		persistent := filepath.Join(root, "data", "42")
		newDefault := filepath.Join(root, "spool", "uploads")
		legacy := filepath.Join(root, "tmp", "uploads")
		if err := os.MkdirAll(persistent, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(persistent, hash), []byte("live"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(newDefault, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(legacy, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(persistent, filepath.Join(newDefault, "42")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(persistent, filepath.Join(legacy, "42")); err != nil {
			t.Fatal(err)
		}
		if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err != nil {
			t.Fatalf("same account directory reachable under both spools refused startup: %v", err)
		}

		// A second account under legacy pointing at persistent while missing under newDefault IS stranded.
		if err := os.Symlink(persistent, filepath.Join(legacy, "99")); err != nil {
			t.Fatal(err)
		}
		if err := CheckLegacyStaging(newDefault, newDefault, legacy, os.Geteuid()); err == nil {
			t.Fatal("legacy account 99 missing under active spool was not refused")
		}
	})
}

func TestCheckLegacyStagingBodyIdentity(t *testing.T) {
	for _, tc := range []struct {
		name          string
		kind          string
		activeAccount string
		wantRefusal   bool
	}{
		{"hard-linked body", "hardlink", "42", false},
		{"symlinked body", "symlink", "42", false},
		{"same bytes in a distinct file", "copy", "42", true},
		{"same body at a different account path", "hardlink", "99", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			legacy, active := filepath.Join(root, "old"), filepath.Join(root, "new")
			hash := strings.Repeat("a", 64)
			legacyBody := filepath.Join(legacy, "42", hash)
			activeBody := filepath.Join(active, tc.activeAccount, hash)
			for _, body := range []string{legacyBody, activeBody} {
				if err := os.MkdirAll(filepath.Dir(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			const payload = "the only staged copy"
			if err := os.WriteFile(legacyBody, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch tc.kind {
			case "hardlink":
				err = os.Link(legacyBody, activeBody)
			case "symlink":
				err = os.Symlink(legacyBody, activeBody)
			case "copy":
				err = os.WriteFile(activeBody, []byte(payload), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = CheckLegacyStaging(active, active, legacy, os.Geteuid())
			if (err != nil) != tc.wantRefusal {
				t.Fatalf("refusal = %v, want %v (error: %v)", err != nil, tc.wantRefusal, err)
			}
			for _, body := range []string{legacyBody, activeBody} {
				data, err := os.ReadFile(body)
				if err != nil || string(data) != payload {
					t.Fatalf("staged body changed at %s: data=%q error=%v", body, data, err)
				}
			}
		})
	}
}

func TestCheckLegacyStagingCycleDoesNotHideStrandedBody(t *testing.T) {
	root := t.TempDir()
	legacy, active := filepath.Join(root, "old"), filepath.Join(root, "new")
	for _, dir := range []string{legacy, active} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	hash := strings.Repeat("a", 64)
	legacyBody := filepath.Join(legacy, hash)
	if err := os.WriteFile(legacyBody, []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(legacyBody, filepath.Join(active, hash)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(legacy, filepath.Join(legacy, "42")); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyStaging(active, active, legacy, os.Geteuid()); err == nil {
		t.Fatal("legacy account 42 reaches a body that is absent under the active account path; want refusal")
	}
	// The alias is safe once its identical subtree is also reachable at the same
	// logical account path under the active spool.
	if err := os.Symlink(legacy, filepath.Join(active, "42")); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyStaging(active, active, legacy, os.Geteuid()); err != nil {
		t.Fatalf("cyclic account alias is reachable through the active spool too: %v", err)
	}
	// The cycle's presence check also follows a body symlink outside the spool.
	if err := os.Remove(filepath.Join(active, "42")); err != nil {
		t.Fatal(err)
	}
	persistentBody := filepath.Join(root, "persistent-body")
	if err := os.WriteFile(persistentBody, []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{legacyBody, filepath.Join(active, hash)} {
		if err := os.Remove(body); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(persistentBody, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckLegacyStaging(active, active, legacy, os.Geteuid()); err == nil {
		t.Fatal("cyclic account alias reaches an external body symlink missing under active account 42; want refusal")
	}
}

// anotherUsersEntries makes the entries at paths belong to another local user, as if that
// user had created them in the shared /tmp, and returns the uid to check as. Only root can
// give a file away; any other user checks as a uid other than its own instead, so every
// file the test made belongs to "another user".
func anotherUsersEntries(t *testing.T, paths ...string) int {
	t.Helper()
	if os.Geteuid() != 0 {
		return os.Geteuid() + 1
	}
	for _, p := range paths {
		if err := os.Lchown(p, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	return 0
}

// TestCheckLegacyStagingIgnoresAnotherUsersSpool: any local user can create the legacy
// default under /tmp. What another user put there holds no body the server staged, and
// must not keep it from starting. sora-admin, which cannot tell who the server runs as,
// still counts it.
func TestCheckLegacyStagingIgnoresAnotherUsersSpool(t *testing.T) {
	hash := strings.Repeat("a", 64)

	t.Run("planted body", func(t *testing.T) {
		root := t.TempDir()
		active, legacy := filepath.Join(root, "spool", "uploads"), filepath.Join(root, "tmp", "sora", "uploads")
		account := filepath.Join(legacy, "x")
		body := filepath.Join(account, hash)
		if err := os.MkdirAll(account, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(body, []byte("planted"), 0o644); err != nil {
			t.Fatal(err)
		}
		uid := anotherUsersEntries(t, filepath.Dir(legacy), legacy, account, body)
		if err := CheckLegacyStaging(active, active, legacy, uid); err != nil {
			t.Fatalf("legacy spool made by another user refused startup: %v", err)
		}
		if err := CheckLegacyStaging(active, active, legacy, AnyOwner); err == nil {
			t.Fatal("AnyOwner: another user's legacy body: want refusal, got nil")
		}
	})

	// A link to someone else's files is no spool: here root's /etc, whose files would
	// count, root being trusted like the user the server runs as.
	t.Run("planted symlink", func(t *testing.T) {
		root := t.TempDir()
		active, legacy := filepath.Join(root, "spool", "uploads"), filepath.Join(root, "tmp", "sora", "uploads")
		if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc", legacy); err != nil {
			t.Fatal(err)
		}
		if err := CheckLegacyStaging(active, active, legacy, os.Geteuid()); err == nil {
			t.Fatal("legacy spool linked by this user to root's files: want refusal, got nil")
		}
		uid := anotherUsersEntries(t, filepath.Dir(legacy), legacy)
		if err := CheckLegacyStaging(active, active, legacy, uid); err != nil {
			t.Fatalf("legacy spool linked by another user to root's files refused startup: %v", err)
		}
	})
}

// TestCheckLegacyStagingIgnoresUnreadableDirectory: another user's /tmp/sora with mode
// 0700 cannot be read by the user the server runs as, nor can a directory of its own
// that it lost access to. Neither holds a body it could upload. sora-admin still refuses:
// what it cannot read, the server may.
func TestCheckLegacyStagingIgnoresUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	for _, unreadable := range []string{"tmp/sora", "tmp/sora/uploads/x"} {
		t.Run(unreadable, func(t *testing.T) {
			root := t.TempDir()
			active, legacy := filepath.Join(root, "spool", "uploads"), filepath.Join(root, "tmp", "sora", "uploads")
			if err := os.MkdirAll(filepath.Join(legacy, "x"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(legacy, "x", strings.Repeat("a", 64)), []byte("planted"), 0o644); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, filepath.FromSlash(unreadable))
			if err := os.Chmod(dir, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(dir, 0o755) })
			if err := CheckLegacyStaging(active, active, legacy, os.Geteuid()); err != nil {
				t.Fatalf("unreadable %s refused startup: %v", unreadable, err)
			}
			if err := CheckLegacyStaging(active, active, legacy, AnyOwner); err == nil {
				t.Fatalf("AnyOwner: unreadable %s: want refusal, got nil", unreadable)
			}
		})
	}
}

// TestCheckLegacyStagingIgnoresAnotherUsersEntries: inside a spool of the user the server
// runs as, a directory or body of another user is passed over, while a body of its own
// still refuses the start. Only root can give a file away.
func TestCheckLegacyStagingIgnoresAnotherUsersEntries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can give a file to another user")
	}
	root := t.TempDir()
	active, legacy := filepath.Join(root, "spool", "uploads"), filepath.Join(root, "tmp", "sora", "uploads")
	hash := strings.Repeat("a", 64)
	for _, dir := range []string{"41", "42"} {
		if err := os.MkdirAll(filepath.Join(legacy, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacy, dir, hash), []byte("planted"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	uid := anotherUsersEntries(t, filepath.Join(legacy, "41"), filepath.Join(legacy, "42", hash))
	if err := CheckLegacyStaging(active, active, legacy, uid); err != nil {
		t.Fatalf("another user's directory and body in the legacy spool refused startup: %v", err)
	}

	own := filepath.Join(legacy, "43", hash)
	if err := os.MkdirAll(filepath.Dir(own), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyStaging(active, active, legacy, uid); err == nil || !strings.Contains(err.Error(), own) {
		t.Fatalf("own body next to another user's entries: want a refusal naming %s, got %v", own, err)
	}
}
