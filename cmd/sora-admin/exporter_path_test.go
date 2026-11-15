package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mailboxDir is the path of the maildir directory (the parent of cur/new/tmp) of an
// IMAP mailbox name: mailboxDirName below the export directory.
func (exporter *Exporter) mailboxDir(mailboxName string) (string, error) {
	name, err := exporter.mailboxDirName(mailboxName)
	if err != nil {
		return "", err
	}
	return filepath.Join(exporter.maildirPath, name), nil
}

// newDirExporter returns an exporter that lays out mailbox directories and files in
// dir, without the export cache NewExporter opens there.
func newDirExporter(t *testing.T, dir string) *Exporter {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return &Exporter{maildirPath: dir, root: root}
}

// TestExporterMailboxDirContainment verifies that mailboxDirName keeps every
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
			// A '.' in a level is escaped, or the importer would read it as the
			// Maildir++ hierarchy separator (#1166).
			{"Foo.Bar", `Foo\2eBar`},
			{"Données/Q1", filepath.Join("Donn&AOk-es", "Q1")},
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

	// Names with a "." or ".." level are rejected, as mailbox creation rejects
	// them (helpers.MailboxNameHasTraversal): no directory names them. That
	// includes names that normalise back inside the root, e.g. "foo/../bar",
	// which would otherwise share the directory of the mailbox "bar".
	t.Run("escaping names are rejected", func(t *testing.T) {
		bad := []string{
			"..",
			".",
			"../etc",
			"../../etc/passwd",
			"foo/..",               // normalises to the root itself
			"Archive/../../secret", // escapes one level above root
			"foo/../bar",           // normalises to the directory of "bar"
		}
		for _, mailbox := range bad {
			dir, err := exporter.mailboxDir(mailbox)
			if err == nil {
				t.Errorf("mailboxDir(%q) = %q, want error (path traversal)", mailbox, dir)
			}
		}
	})
}
