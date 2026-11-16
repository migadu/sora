package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An export merges into what its destination already holds (dovecot-uidlist,
// dovecot-keywords), so it may be given a maildir its owner could write to, and it runs
// with privileges the owner lacks. No link in the destination may have the export write
// a file outside it, at any level (#1597): a metadata file or a message file is
// replaced, not written through, and a mailbox directory, cur/, new/ or tmp/ linked out
// of the destination is refused. This is the export's side of #1548.

// linkOut makes link a symbolic link to target, absolute or relative to link's directory.
func linkOut(t *testing.T, target, link string, relative bool) {
	t.Helper()
	if relative {
		target = relativeLink(t, link, target)
	}
	require.NoError(t, os.Symlink(target, link))
}

// newLinkTestExporter returns an exporter writing to a fresh destination, and the
// destination with INBOX's cur/, new/ and tmp/ created.
func newLinkTestExporter(t *testing.T, s3 objectStorage, options ExporterOptions) (*Exporter, string) {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "Maildir")
	exporter, err := NewExporter(context.Background(), dest, "user@example.com", 1, nil, s3, options)
	require.NoError(t, err)
	t.Cleanup(func() { exporter.Close() })
	require.NoError(t, exporter.createMailboxDirectory("INBOX"))
	return exporter, dest
}

// assertRegularFile asserts that path is a file of its own, not a link to another.
func assertRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if assert.NoError(t, err) {
		assert.True(t, info.Mode().IsRegular(), "%s is %v, not a regular file", path, info.Mode())
	}
}

// assertUnchanged asserts that the file at path still holds content.
func assertUnchanged(t *testing.T, path string, content []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(content), string(got), "the export wrote %s outside its destination", path)
}

// assertEmptyDir asserts that the directory at path holds nothing.
func assertEmptyDir(t *testing.T, path string) {
	t.Helper()
	assert.Empty(t, dirNames(t, path), "the export wrote into %s outside its destination", path)
}

// linkKinds are the links the destination's owner can put at the name of a file the
// export reads back and replaces. A hard link is another name for the same file, which
// the root cannot tell from a file an earlier run wrote (#1671): one on the same file
// system as its target, where the system lets the owner link a file they cannot read
// (BSD and macOS do, as Linux does with fs.protected_hardlinks = 0).
var linkKinds = []struct {
	name string
	link func(t *testing.T, target, link string)
}{
	{"absolute link", func(t *testing.T, target, link string) { linkOut(t, target, link, false) }},
	{"relative link", func(t *testing.T, target, link string) { linkOut(t, target, link, true) }},
	{"hard link", func(t *testing.T, target, link string) { require.NoError(t, os.Link(target, link)) }},
}

func TestExportReplacesLinkedDovecotUIDList(t *testing.T) {
	// An entry of the file the link names is merged when a file of its name is in cur/
	// (mergeUIDMappings), which the owner can arrange: its UID would be written out.
	const ownersFile = "1700000009.M9P9.host"
	secret := []byte("3 V99 N6\n5 :" + ownersFile + "\n")
	for _, tc := range linkKinds {
		t.Run(tc.name, func(t *testing.T) {
			outside := outsideFile(t, secret)
			exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{ExportUIDList: true})
			require.NoError(t, os.WriteFile(filepath.Join(dest, "cur", ownersFile+":2,S"), nil, 0644))
			uidlist := filepath.Join(dest, "dovecot-uidlist")
			tc.link(t, outside, uidlist)

			exporter.uidMappings["INBOX"] = []UIDFileMapping{{UID: 7, Filename: "1700000001.M1P1.host"}}
			require.NoError(t, exporter.generateDovecotUIDLists([]*db.DBMailbox{{Name: "INBOX", UIDValidity: 42}}))

			assertUnchanged(t, outside, secret)
			assertRegularFile(t, uidlist)
			written, err := ParseDovecotUIDList(dest)
			require.NoError(t, err)
			require.NotNil(t, written)
			assert.Equal(t, uint32(42), written.UIDValidity)
			assert.Equal(t, map[string]uint32{"1700000001.M1P1.host": 7}, written.UIDMappings,
				"an entry of the uidlist read through the link was carried into the export")
		})
	}
}

func TestExportReplacesLinkedDovecotKeywords(t *testing.T) {
	secret := []byte("0 $Secret\n")
	for _, tc := range linkKinds {
		t.Run(tc.name, func(t *testing.T) {
			outside := outsideFile(t, secret)
			exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{Dovecot: true})
			keywords := filepath.Join(dest, "dovecot-keywords")
			tc.link(t, outside, keywords)

			require.NoError(t, exporter.prepareKeywords("INBOX", []db.Message{{UID: 1, CustomFlags: []string{"$Work"}}}))

			assertUnchanged(t, outside, secret)
			assertRegularFile(t, keywords)
			got, err := os.ReadFile(keywords)
			require.NoError(t, err)
			assert.Equal(t, "0 $Work\n", string(got), "the keywords file read through the link was carried into the export")
		})
	}
}

// messageStorage serves one message for every key.
type messageStorage struct{ content []byte }

func (s messageStorage) Put(string, io.Reader, int64) error { return nil }
func (s messageStorage) Get(string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.content)), nil
}
func (s messageStorage) Exists(string) (bool, string, error) { return true, "", nil }
func (s messageStorage) Delete(string) error                 { return nil }
func (s messageStorage) Copy(string, string) error           { return nil }
func (s messageStorage) EnableEncryption(string) error       { return nil }

func linkTestMessage() db.Message {
	return db.Message{
		UID:          3,
		InternalDate: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
		ContentHash:  "0123456789abcdef0123456789abcdef",
		S3Domain:     "example.com",
		S3Localpart:  "user",
	}
}

const linkTestMessageBody = "From: sender@example.com\r\nSubject: Exported\r\n\r\nBody\r\n"

func TestExportMessageDoesNotWriteThroughLinkedTmpFile(t *testing.T) {
	secret := []byte("root:secret-hash:19000:0:99999:7:::\n")
	outside := outsideFile(t, secret)
	exporter, dest := newLinkTestExporter(t, messageStorage{[]byte(linkTestMessageBody)}, ExporterOptions{})
	msg := linkTestMessage()
	filename := exporter.generateMaildirFilename(&msg, "INBOX")
	// The name the export stages the message under in tmp/ before renaming it into cur/.
	linkOut(t, outside, filepath.Join(dest, "tmp", filename), false)

	require.NoError(t, exporter.exportMessage(&msg, "INBOX"))

	assertUnchanged(t, outside, secret)
	target := filepath.Join(dest, "cur", filename)
	assertRegularFile(t, target)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, linkTestMessageBody, string(got))
}

func TestExportMessageRefusesLinkedMaildirDirectories(t *testing.T) {
	for _, sub := range []string{"cur", "tmp"} {
		for _, relative := range []bool{false, true} {
			t.Run(sub+map[bool]string{false: " absolute link", true: " relative link"}[relative], func(t *testing.T) {
				outsideDir := t.TempDir()
				exporter, dest := newLinkTestExporter(t, messageStorage{[]byte(linkTestMessageBody)}, ExporterOptions{})
				require.NoError(t, os.Remove(filepath.Join(dest, sub)))
				linkOut(t, outsideDir, filepath.Join(dest, sub), relative)

				msg := linkTestMessage()
				err := exporter.exportMessage(&msg, "INBOX")

				assert.Error(t, err, "a message was exported through %s/ linked out of the destination", sub)
				assertEmptyDir(t, outsideDir)
			})
		}
	}

	// A link to a directory of the same destination writes nothing outside it, and is
	// written through as before.
	t.Run("cur link within the destination", func(t *testing.T) {
		exporter, dest := newLinkTestExporter(t, messageStorage{[]byte(linkTestMessageBody)}, ExporterOptions{})
		require.NoError(t, exporter.createMailboxDirectory("Sent"))
		require.NoError(t, os.Remove(filepath.Join(dest, "cur")))
		linkOut(t, filepath.Join(dest, "Sent", "cur"), filepath.Join(dest, "cur"), true)

		msg := linkTestMessage()
		require.NoError(t, exporter.exportMessage(&msg, "INBOX"))

		got, err := os.ReadFile(filepath.Join(dest, "Sent", "cur", exporter.generateMaildirFilename(&msg, "INBOX")))
		require.NoError(t, err)
		assert.Equal(t, linkTestMessageBody, string(got))
	})
}

func TestExportRefusesLinkedMailboxDirectory(t *testing.T) {
	// The directories the export creates (createMailboxDirectory, which Run calls for
	// every mailbox before it writes a message): a mailbox's own, and INBOX's cur/,
	// new/ and tmp/ in the destination itself.
	for _, tc := range []struct{ mailbox, link string }{
		{"Work", "Work"},
		{"INBOX", "cur"},
		{"INBOX", "new"},
		{"INBOX", "tmp"},
	} {
		for _, relative := range []bool{false, true} {
			t.Run(tc.link+map[bool]string{false: " absolute link", true: " relative link"}[relative], func(t *testing.T) {
				outsideDir := t.TempDir()
				exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{})
				link := filepath.Join(dest, tc.link)
				require.NoError(t, os.RemoveAll(link))
				linkOut(t, outsideDir, link, relative)

				err := exporter.createMailboxDirectory(tc.mailbox)

				assert.Error(t, err, "%s linked out of the destination was accepted", tc.link)
				assertEmptyDir(t, outsideDir)
			})
		}
	}
}
