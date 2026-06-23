package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestExporterMailboxDirContainment verifies that mailboxDir keeps every
// resolved path within the export root, blocking path traversal via ".."
// mailbox names (M5).
func TestExporterMailboxDirContainment(t *testing.T) {
	root := t.TempDir()
	exporter := &Exporter{maildirPath: root}

	t.Run("safe names stay inside root", func(t *testing.T) {
		cases := []struct {
			mailbox string
			wantRel string // path relative to root; "." means root (INBOX)
		}{
			{"INBOX", "."},
			{"Sent", "Sent"},
			{"Archive/2024", filepath.Join("Archive", "2024")},
			{"Foo.Bar", "Foo.Bar"},
		}
		for _, c := range cases {
			dir, err := exporter.mailboxDir(c.mailbox)
			if err != nil {
				t.Fatalf("mailboxDir(%q) returned error: %v", c.mailbox, err)
			}
			want := filepath.Join(root, c.wantRel)
			if dir != want {
				t.Errorf("mailboxDir(%q) = %q, want %q", c.mailbox, dir, want)
			}
			// Sanity: result must be contained in root.
			rel, _ := filepath.Rel(root, dir)
			if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Errorf("mailboxDir(%q) escaped root: rel=%q", c.mailbox, rel)
			}
		}
	})

	// Names whose ".." segments make the path escape the export root must be
	// rejected. (Names with contained ".." that normalise back inside the root,
	// e.g. "foo/../bar" -> "<root>/bar", are not an escape and are blocked
	// earlier at mailbox creation by helpers.MailboxNameHasTraversal.)
	t.Run("escaping names are rejected", func(t *testing.T) {
		bad := []string{
			"..",
			".",
			"../etc",
			"../../etc/passwd",
			"foo/..",               // normalises to the root itself
			"Archive/../../secret", // escapes one level above root
		}
		for _, mailbox := range bad {
			dir, err := exporter.mailboxDir(mailbox)
			if err == nil {
				t.Errorf("mailboxDir(%q) = %q, want error (path traversal)", mailbox, dir)
			}
		}
	})
}
