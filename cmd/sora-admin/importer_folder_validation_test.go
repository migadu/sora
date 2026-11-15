package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportedFolderNameRejectsInvalidMailboxNames(t *testing.T) {
	root := t.TempDir()
	importer := &Importer{maildirPath: root}

	subsNUL := parseDovecotSubscriptions("V\t2\n\nFoo\x010Bar\n")
	require.Equal(t, []string{"Foo\x00Bar"}, subsNUL)

	subsEmptyLevel := parseDovecotSubscriptions("V\t2\n\nWork\t\tSecret\n")
	require.Equal(t, []string{"Work//Secret"}, subsEmptyLevel)

	invalidInputs := []struct {
		label string
		raw   string
	}{
		{"escaped single dot", `\2e`},
		{"escaped double dot", `\2e\2e`},
		{"escaped dot in hierarchy", `Work/\2e/Secret`},
		{"escaped traversal in hierarchy", `Work/\2e\2e/Secret`},
		{"escaped trailing traversal", `Work/\2e\2e`},
		{"empty hierarchy level", "Work//Secret"},
		{"subscription empty level", subsEmptyLevel[0]},
		{"leading delimiter", "/Work"},
		{"escaped space before leading delimiter", `\20/Work`},
		{"trailing delimiter", "Work/"},
		{"escaped space after trailing delimiter", `Work/\20`},
		{"subscription NUL via tab unescape", subsNUL[0]},
		{"modified UTF-7 NUL", "Foo&AAA-Bar"},
		{"modified UTF-7 TAB", "Foo&AAk-Bar"},
		{"modified UTF-7 CR", "Foo&AA0-Bar"},
		{"modified UTF-7 LF", "Foo&AAo-Bar"},
		{"invalid UTF-8 Latin-1", "Caf\xe9"},
		{"invalid UTF-8 byte in level", "Work/\xff/Secret"},
	}

	for _, tc := range invalidInputs {
		t.Run("reject_"+tc.label, func(t *testing.T) {
			got, err := importedFolderName(tc.raw)
			assert.Error(t, err, "importedFolderName(%q) returned %q without error", tc.raw, got)
		})
	}

	invalidMaildirDirs := []string{
		`.\2e`,
		`.\2e\2e`,
		`.Work.\2e\2e.Secret`,
		`.Work..Secret`,
		`..Work`,
		`.Work.`,
		".Foo&AAA-Bar",
		".Caf\xe9",
	}
	for _, dir := range invalidMaildirDirs {
		t.Run("resolve_reject_"+dir, func(t *testing.T) {
			got, err := importer.resolveMailboxName(filepath.Join(root, dir))
			assert.Error(t, err, "resolveMailboxName(%q) returned %q without error", dir, got)
		})
	}

	validInputs := []struct {
		raw  string
		want string
	}{
		{`v1\2e0`, "v1.0"},
		{`Work/v1\2e2/Notes`, "Work/v1.2/Notes"},
		{`a\5cb`, `a\b`},
		{`\2ehidden`, ".hidden"},
		{`\2e\2efoo`, "..foo"},
		{`a\1fb`, `a\1fb`},
		{`a\7fb`, `a\7fb`},
		{"Caf&AOk-", "Café"},
		{"Café", "Café"},
		{"Sent Items", "Sent"},
	}
	for _, tc := range validInputs {
		t.Run("accept_"+tc.raw, func(t *testing.T) {
			got, err := importedFolderName(tc.raw)
			if assert.NoError(t, err, tc.raw) {
				assert.Equal(t, tc.want, got, tc.raw)
			}
		})
	}
}

func TestScanMaildirSkipsInvalidMailboxFolders(t *testing.T) {
	root := t.TempDir()
	exporter := &Exporter{maildirPath: root}
	require.NoError(t, exporter.createMailboxDirectory("INBOX"))

	folders := []string{
		`.Work.Secret`,
		`.Work.\2e\2e.Secret`,
		`.\2e\2e`,
		`.Work..Secret`,
		".Foo&AAA-Bar",
	}
	for idx, name := range folders {
		dir := filepath.Join(root, name)
		for _, sub := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
		}
		filename := fmt.Sprintf("1700000000.M%dP1.host:2,S", idx+1)
		body := fmt.Sprintf("Subject: folder %d\r\n\r\nbody %d\r\n", idx+1, idx+1)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cur", filename), []byte(body), 0o644))
	}

	importer := newTestModeImporter(t, root, newMockResilientDatabase(), ImporterOptions{})
	require.NoError(t, importer.scanMaildir())

	rows, err := importer.sqliteDB.Query(`SELECT mailbox FROM messages ORDER BY mailbox`)
	require.NoError(t, err)
	defer rows.Close()

	var mailboxes []string
	for rows.Next() {
		var mbox string
		require.NoError(t, rows.Scan(&mbox))
		mailboxes = append(mailboxes, mbox)
	}
	require.NoError(t, rows.Err())

	assert.Equal(t, []string{"Work/Secret"}, mailboxes, "invalid folders must be skipped before queueing messages for S3 upload")
}

type recordingSubMockDB struct {
	*mockResilientDatabase
	subscribed []string
}

func (r *recordingSubMockDB) SubscribeWithRetry(ctx context.Context, accountID int64, mailboxName string) error {
	r.subscribed = append(r.subscribed, mailboxName)
	return nil
}

func TestProcessSubscriptionsSkipsInvalidMailboxNames(t *testing.T) {
	root := t.TempDir()
	subsContent := "V\t2\n\nINBOX\n\\2e\n\\2e\\2e\nWork\t\\2e\\2e\tSecret\nWork\t\tSecret\nFoo\x010Bar\nFoo&AAA-Bar\nCaf\xe9\nv1\\2e0\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "subscriptions"), []byte(subsContent), 0o644))

	mockDB := &recordingSubMockDB{mockResilientDatabase: newMockResilientDatabase()}
	importer := newTestModeImporter(t, root, mockDB, ImporterOptions{Dovecot: true})

	require.NoError(t, importer.processSubscriptions())
	assert.Equal(t, []string{"INBOX", "v1.0"}, mockDB.subscribed)
}
