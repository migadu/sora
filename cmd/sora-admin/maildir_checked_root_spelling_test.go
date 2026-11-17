package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEffectiveMaildirPathUsesCheckedRootWhenDotDotLinkReplaced(t *testing.T) {
	const aliceName = "1700000001.M1P1.host:2,S"
	const bobName = "1700000002.M2P1.host:2,S"
	sep := string(filepath.Separator)

	t.Run("retargeted to victim Maildir", func(t *testing.T) {
		setup := func(t *testing.T) (maildirPath, target, victim string, swapLink func()) {
			t.Helper()
			base, err := filepath.EvalSymlinks(t.TempDir())
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Join(base, "a", "b"), 0755))
			target = filepath.Join(base, "a", "Maildir")
			for _, sub := range []string{"cur", "new", "tmp"} {
				require.NoError(t, os.MkdirAll(filepath.Join(target, sub), 0755))
			}
			require.NoError(t, os.WriteFile(filepath.Join(target, "cur", aliceName), cachedSizeMessage("Alice", 100), 0644))

			victimParent := filepath.Join(base, "victim-parent")
			require.NoError(t, os.MkdirAll(filepath.Join(victimParent, "b"), 0755))
			victim = filepath.Join(victimParent, "Maildir")
			for _, sub := range []string{"cur", "new", "tmp"} {
				require.NoError(t, os.MkdirAll(filepath.Join(victim, sub), 0755))
			}
			require.NoError(t, os.WriteFile(filepath.Join(victim, "cur", bobName), cachedSizeMessage("Bob", 100), 0644))

			link := filepath.Join(base, "link")
			require.NoError(t, os.Symlink(filepath.Join(base, "a", "b"), link))
			maildirPath = link + sep + ".." + sep + "Maildir"
			swapLink = func() {
				require.NoError(t, os.Remove(link))
				require.NoError(t, os.Symlink(filepath.Join(victimParent, "b"), link))
			}
			return maildirPath, target, victim, swapLink
		}

		t.Run("import", func(t *testing.T) {
			maildirPath, target, victim, swapLink := setup(t)
			victimBefore := treeOf(t, victim)
			importRootOpened = swapLink
			t.Cleanup(func() { importRootOpened = nil })

			importer, err := NewImporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			require.NoError(t, err)
			t.Cleanup(func() { importer.Close() })
			importer.rdb = newMockResilientDatabase()

			assert.Equal(t, target, importer.maildirPath, "importer.maildirPath resolved the retargeted link to victim instead of the checked root")
			assert.Equal(t, filepath.Join(target, maildirCacheName), importer.dbPath)
			require.NoError(t, importer.scanMaildir())
			assert.Equal(t, map[string]string{
				filepath.Join(target, "cur", aliceName): "INBOX",
			}, scannedMessages(t, importer), "scanMaildir recorded victim's prefix in the checked cache")
			assert.Equal(t, victimBefore, treeOf(t, victim))
		})

		t.Run("export", func(t *testing.T) {
			maildirPath, target, victim, swapLink := setup(t)
			victimBefore := treeOf(t, victim)
			exportRootOpened = swapLink
			t.Cleanup(func() { exportRootOpened = nil })

			exporter, err := NewExporter(context.Background(), maildirPath, "alice@example.com", 1, nil, messageStorage{[]byte(linkTestMessageBody)}, ExporterOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { exporter.Close() })

			assert.Equal(t, target, exporter.maildirPath, "exporter.maildirPath resolved the retargeted link to victim instead of the checked root")
			assert.Equal(t, filepath.Join(target, maildirCacheName), exporter.dbPath)

			msg := linkTestMessage()
			filename := exporter.generateMaildirFilename(&msg, "INBOX")
			require.NoError(t, exporter.createMailboxDirectory("INBOX"))
			require.NoError(t, exporter.exportMessage(&msg, "INBOX"))
			var recordedPath string
			require.NoError(t, exporter.db.QueryRow(`SELECT path FROM messages`).Scan(&recordedPath))
			assert.Equal(t, filepath.Join(target, "cur", filename), recordedPath, "recordExport wrote victim's prefix into the checked cache")
			assert.Equal(t, victimBefore, treeOf(t, victim))
		})

		t.Run("export dry-run", func(t *testing.T) {
			maildirPath, target, victim, swapLink := setup(t)
			exportRootOpened = swapLink
			t.Cleanup(func() { exportRootOpened = nil })

			exporter, err := NewExporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
			require.NoError(t, err)
			t.Cleanup(func() { exporter.Close() })

			assert.Equal(t, target, exporter.maildirPath, "dry-run exporter.maildirPath resolved the retargeted link to victim instead of the checked root")
			assert.Equal(t, filepath.Join(target, maildirCacheName), exporter.dbPath)
			_ = victim
		})
	})

	t.Run("retargeted to sibling decoy Maildir", func(t *testing.T) {
		setup := func(t *testing.T) (relPath, target, decoy string, swapLink func()) {
			t.Helper()
			base, err := filepath.EvalSymlinks(t.TempDir())
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Join(base, "a", "b"), 0755))
			require.NoError(t, os.MkdirAll(filepath.Join(base, "b"), 0755))
			target = filepath.Join(base, "a", "Maildir")
			decoy = filepath.Join(base, "Maildir")
			for _, dir := range []string{target, decoy} {
				for _, sub := range []string{"cur", "new", "tmp"} {
					require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0755))
				}
			}
			require.NoError(t, os.WriteFile(filepath.Join(target, "cur", aliceName), cachedSizeMessage("Alice", 100), 0644))
			require.NoError(t, os.WriteFile(filepath.Join(decoy, "cur", bobName), cachedSizeMessage("Decoy", 100), 0644))

			link := filepath.Join(base, "link")
			require.NoError(t, os.Symlink(filepath.Join(base, "a", "b"), link))
			t.Chdir(base)
			relPath = "link" + sep + ".." + sep + "Maildir"
			swapLink = func() {
				require.NoError(t, os.Remove(link))
				require.NoError(t, os.Symlink(filepath.Join(base, "b"), link))
			}
			return relPath, target, decoy, swapLink
		}

		t.Run("import", func(t *testing.T) {
			relPath, target, decoy, swapLink := setup(t)
			decoyBefore := treeOf(t, decoy)
			importRootOpened = swapLink
			t.Cleanup(func() { importRootOpened = nil })

			importer, err := NewImporter(context.Background(), relPath, "alice@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			require.NoError(t, err)
			t.Cleanup(func() { importer.Close() })
			importer.rdb = newMockResilientDatabase()

			assert.Equal(t, target, importer.maildirPath, "effectiveMaildirPath kept link/../Maildir whose Clean collapses onto sibling decoy ./Maildir")
			assert.Equal(t, filepath.Join(target, maildirCacheName), importer.dbPath)
			require.NoError(t, importer.scanMaildir())
			assert.Equal(t, map[string]string{
				filepath.Join(target, "cur", aliceName): "INBOX",
			}, scannedMessages(t, importer))
			assert.Equal(t, decoyBefore, treeOf(t, decoy))
		})

		t.Run("export", func(t *testing.T) {
			relPath, target, decoy, swapLink := setup(t)
			decoyBefore := treeOf(t, decoy)
			exportRootOpened = swapLink
			t.Cleanup(func() { exportRootOpened = nil })

			exporter, err := NewExporter(context.Background(), relPath, "alice@example.com", 1, nil, messageStorage{[]byte(linkTestMessageBody)}, ExporterOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { exporter.Close() })

			assert.Equal(t, target, exporter.maildirPath, "effectiveMaildirPath kept link/../Maildir whose Clean collapses onto sibling decoy ./Maildir")
			assert.Equal(t, filepath.Join(target, maildirCacheName), exporter.dbPath)

			msg := linkTestMessage()
			filename := exporter.generateMaildirFilename(&msg, "INBOX")
			require.NoError(t, exporter.createMailboxDirectory("INBOX"))
			require.NoError(t, exporter.exportMessage(&msg, "INBOX"))
			var recordedPath string
			require.NoError(t, exporter.db.QueryRow(`SELECT path FROM messages`).Scan(&recordedPath))
			assert.Equal(t, filepath.Join(target, "cur", filename), recordedPath)
			assert.Equal(t, decoyBefore, treeOf(t, decoy))
		})

		t.Run("export dry-run", func(t *testing.T) {
			relPath, target, _, swapLink := setup(t)
			exportRootOpened = swapLink
			t.Cleanup(func() { exportRootOpened = nil })

			exporter, err := NewExporter(context.Background(), relPath, "alice@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
			require.NoError(t, err)
			t.Cleanup(func() { exporter.Close() })

			assert.Equal(t, target, exporter.maildirPath, "dry-run effectiveMaildirPath kept link/../Maildir whose Clean collapses onto sibling decoy ./Maildir")
			assert.Equal(t, filepath.Join(target, maildirCacheName), exporter.dbPath)
		})
	})
}

func TestMaildirNameUsesCheckedRootWhenGivenPathReplaced(t *testing.T) {
	const msgName = "1700000001.M1P1.host:2,S"

	for _, tc := range []struct {
		name      string
		cacheVia  func(realDir, altLink string) string
		mutateRun func(t *testing.T, run2Link, victim string)
	}{
		{
			name:     "cached under real path, run2 link retargeted to victim",
			cacheVia: func(realDir, _ string) string { return realDir },
			mutateRun: func(t *testing.T, run2Link, victim string) {
				require.NoError(t, os.Remove(run2Link))
				require.NoError(t, os.Symlink(victim, run2Link))
			},
		},
		{
			name:     "cached under real path, run2 link removed",
			cacheVia: func(realDir, _ string) string { return realDir },
			mutateRun: func(t *testing.T, run2Link, _ string) {
				require.NoError(t, os.Remove(run2Link))
			},
		},
		{
			name:     "cached under alternate symlink, run2 link retargeted to victim",
			cacheVia: func(_, altLink string) string { return altLink },
			mutateRun: func(t *testing.T, run2Link, victim string) {
				require.NoError(t, os.Remove(run2Link))
				require.NoError(t, os.Symlink(victim, run2Link))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realDir := newMaildirWith(t, map[string][]byte{msgName: cachedSizeMessage("Target", 100)})
			realDir, err := filepath.EvalSymlinks(realDir)
			require.NoError(t, err)
			victim := newMaildirWith(t, map[string][]byte{msgName: cachedSizeMessage("Victim", 100)})
			victimBefore := treeOf(t, victim)

			linksDir, err := filepath.EvalSymlinks(t.TempDir())
			require.NoError(t, err)
			altLink := filepath.Join(linksDir, "alt-link")
			run2Link := filepath.Join(linksDir, "run2-link")
			require.NoError(t, os.Symlink(realDir, altLink))
			require.NoError(t, os.Symlink(realDir, run2Link))

			// Run 1 caches msgName under an earlier spelling of the maildir.
			earlier := newTestModeImporter(t, tc.cacheVia(realDir, altLink), newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, earlier.scanMaildir())
			require.NoError(t, earlier.Close())

			// Run 2 opens via run2Link, which is replaced/removed right after openImportRoot.
			importRootOpened = func() { tc.mutateRun(t, run2Link, victim) }
			t.Cleanup(func() { importRootOpened = nil })

			rdb := &dotDotRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
			importer, err := NewImporter(context.Background(), run2Link, "alice@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			require.NoError(t, err)
			t.Cleanup(func() { importer.Close() })
			importer.rdb = rdb

			require.NoError(t, importer.Run())
			assert.Equal(t, int64(1), importer.importedMessages)
			assert.Zero(t, importer.failedMessages)
			if assert.Len(t, rdb.inserted, 1) {
				assert.Equal(t, "Target", rdb.inserted[0].Subject)
			}
			assert.Equal(t, victimBefore, treeOf(t, victim))
		})
	}
}

func TestImportPreservesUIDsAndInboxKeywordsAcrossCachedMaildirSpellings(t *testing.T) {
	t.Run("cached by earlier dry-run under real path, imported via symlink", func(t *testing.T) {
		realDir, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)
		sentDir := filepath.Join(realDir, ".Sent")
		for _, dir := range []string{realDir, sentDir} {
			for _, sub := range []string{"cur", "new", "tmp"} {
				require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0755))
			}
		}

		const inboxBase = "1700000001.M1P1.host"
		const inboxFile = inboxBase + ":2,Sa"
		const sentBase = "1700000002.M2P1.host"
		const sentFile = sentBase + ":2,Sa"

		require.NoError(t, os.WriteFile(filepath.Join(realDir, "cur", inboxFile), cachedSizeMessage("Inbox Msg", 120), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sentDir, "cur", sentFile), cachedSizeMessage("Sent Msg", 120), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(realDir, "dovecot-uidlist"),
			[]byte(fmt.Sprintf("3 V111111 N50\n42 :%s\n", inboxBase)), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sentDir, "dovecot-uidlist"),
			[]byte(fmt.Sprintf("3 V222222 N80\n77 :%s\n", sentBase)), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(realDir, "dovecot-keywords"),
			[]byte("0 $InboxLabel\nmalformed_line\n"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sentDir, "dovecot-keywords"),
			[]byte("0 $SentLabel\n"), 0644))

		// Run 1: dry-run on realDir populates sora-maildir.db with realDir's paths.
		dryRunImp, err := NewImporter(context.Background(), realDir, "alice@example.com", 1, nil, nil, ImporterOptions{
			TestMode:      true,
			DryRun:        true,
			Dovecot:       true,
			PreserveFlags: true,
			PreserveUIDs:  true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { dryRunImp.Close() })
		dryRunImp.rdb = newMockResilientDatabase()
		_ = captureStdout(t, func() error {
			require.NoError(t, dryRunImp.Run())
			return nil
		})

		// Run 2: import via a symlink spelling to the same maildir.
		linkDir := filepath.Join(t.TempDir(), "alice-link")
		require.NoError(t, os.Symlink(realDir, linkDir))

		rdb := &dotDotRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		imp, err := NewImporter(context.Background(), linkDir, "alice@example.com", 1, nil, nil, ImporterOptions{
			TestMode:      true,
			Dovecot:       true,
			PreserveFlags: true,
			PreserveUIDs:  true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { imp.Close() })
		imp.rdb = rdb

		require.NoError(t, imp.lookupAccount())
		require.NoError(t, imp.recoverOrphanedSQLiteState())
		require.NoError(t, imp.scanMaildir())
		imp.totalMessages = 2

		logs := &importLogBuffer{}
		prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
		err = imp.importMessages()
		logger.Swap(prev)
		require.NoError(t, err)

		assert.Equal(t, int64(2), imp.importedMessages)
		assert.Zero(t, imp.failedMessages)
		require.Len(t, rdb.inserted, 2)

		byMailbox := make(map[string]*db.InsertMessageOptions, 2)
		for _, ins := range rdb.inserted {
			byMailbox[ins.MailboxName] = ins
		}

		if inbox := byMailbox["INBOX"]; assert.NotNil(t, inbox, "missing INBOX insert") {
			if assert.NotNil(t, inbox.PreservedUID, "INBOX preserved UID lost across cached maildir spellings") {
				assert.Equal(t, uint32(42), *inbox.PreservedUID)
			}
			if assert.NotNil(t, inbox.PreservedUIDValidity, "INBOX preserved UIDVALIDITY lost across cached maildir spellings") {
				assert.Equal(t, uint32(111111), *inbox.PreservedUIDValidity)
			}
			assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen, imap.Flag("$InboxLabel")}, inbox.Flags)
		}

		if sent := byMailbox["Sent"]; assert.NotNil(t, sent, "missing Sent insert") {
			if assert.NotNil(t, sent.PreservedUID, "Sent preserved UID lost across cached maildir spellings") {
				assert.Equal(t, uint32(77), *sent.PreservedUID)
			}
			if assert.NotNil(t, sent.PreservedUIDValidity, "Sent preserved UIDVALIDITY lost across cached maildir spellings") {
				assert.Equal(t, uint32(222222), *sent.PreservedUIDValidity)
			}
			assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen, imap.Flag("$SentLabel")}, sent.Flags)
		}

		// INBOX's dovecot-keywords was already parsed in NewImporter; importMessages must
		// use imp.dovecotKeywords rather than re-parsing INBOX's file from disk.
		assert.NotContains(t, logs.String(), "Skipping malformed dovecot-keywords lines",
			"INBOX dovecot-keywords was re-parsed from disk instead of using imp.dovecotKeywords")
		assert.NotContains(t, logs.String(), filepath.Join(realDir, "dovecot-keywords"),
			"INBOX dovecot-keywords was loaded as a subfolder keywords file")
	})

	t.Run("cached by export maildir under real path, imported via symlink", func(t *testing.T) {
		realDir, err := filepath.EvalSymlinks(t.TempDir())
		require.NoError(t, err)

		const inboxBody = "From: a@example.com\r\nSubject: Exported Inbox\r\nMessage-ID: <exp-inbox@example.com>\r\n\r\nInbox body\r\n"
		const sentBody = "From: a@example.com\r\nSubject: Exported Sent\r\nMessage-ID: <exp-sent@example.com>\r\n\r\nSent body\r\n"

		exporter, err := NewExporter(context.Background(), realDir, "alice@example.com", 1, nil, messageStorage{[]byte(inboxBody)}, ExporterOptions{
			Dovecot:       true,
			ExportUIDList: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { exporter.Close() })

		inboxMsg := db.Message{
			UID:          101,
			InternalDate: time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
			ContentHash:  helpers.HashContent([]byte(inboxBody)),
			S3Domain:     "example.com",
			S3Localpart:  "alice",
			CustomFlags:  []string{"$ExportInbox"},
			BitwiseFlags: db.FlagSeen,
		}
		sentMsg := db.Message{
			UID:          202,
			InternalDate: time.Date(2026, 2, 1, 13, 0, 0, 0, time.UTC),
			ContentHash:  helpers.HashContent([]byte(sentBody)),
			S3Domain:     "example.com",
			S3Localpart:  "alice",
			CustomFlags:  []string{"$ExportSent"},
			BitwiseFlags: db.FlagSeen,
		}

		require.NoError(t, exporter.createMailboxDirectory("INBOX"))
		require.NoError(t, exporter.prepareKeywords("INBOX", []db.Message{inboxMsg}))
		require.NoError(t, exporter.exportMessage(&inboxMsg, "INBOX"))

		exporter.s3 = messageStorage{[]byte(sentBody)}
		require.NoError(t, exporter.createMailboxDirectory("Sent"))
		require.NoError(t, exporter.prepareKeywords("Sent", []db.Message{sentMsg}))
		require.NoError(t, exporter.exportMessage(&sentMsg, "Sent"))

		require.NoError(t, exporter.generateDovecotUIDLists([]*db.DBMailbox{
			{Name: "INBOX", UIDValidity: 333333},
			{Name: "Sent", UIDValidity: 444444},
		}))
		require.NoError(t, exporter.Close())

		linkDir := filepath.Join(t.TempDir(), "exported-link")
		require.NoError(t, os.Symlink(realDir, linkDir))

		rdb := &dotDotRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		imp, err := NewImporter(context.Background(), linkDir, "alice@example.com", 1, nil, nil, ImporterOptions{
			TestMode:      true,
			Dovecot:       true,
			PreserveFlags: true,
			PreserveUIDs:  true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { imp.Close() })
		imp.rdb = rdb

		require.NoError(t, imp.lookupAccount())
		require.NoError(t, imp.recoverOrphanedSQLiteState())
		require.NoError(t, imp.scanMaildir())
		imp.totalMessages = 2

		logs := &importLogBuffer{}
		prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
		err = imp.importMessages()
		logger.Swap(prev)
		require.NoError(t, err)

		require.Len(t, rdb.inserted, 2)
		byMailbox := make(map[string]*db.InsertMessageOptions, 2)
		for _, ins := range rdb.inserted {
			byMailbox[ins.MailboxName] = ins
		}

		if inbox := byMailbox["INBOX"]; assert.NotNil(t, inbox, "missing INBOX insert") {
			if assert.NotNil(t, inbox.PreservedUID, "exported INBOX preserved UID lost on symlink import") {
				assert.Equal(t, uint32(101), *inbox.PreservedUID)
			}
			if assert.NotNil(t, inbox.PreservedUIDValidity, "exported INBOX preserved UIDVALIDITY lost on symlink import") {
				assert.Equal(t, uint32(333333), *inbox.PreservedUIDValidity)
			}
			assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen, imap.Flag("$ExportInbox")}, inbox.Flags)
		}

		if sent := byMailbox["Sent"]; assert.NotNil(t, sent, "missing Sent insert") {
			if assert.NotNil(t, sent.PreservedUID, "exported Sent preserved UID lost on symlink import") {
				assert.Equal(t, uint32(202), *sent.PreservedUID)
			}
			if assert.NotNil(t, sent.PreservedUIDValidity, "exported Sent preserved UIDVALIDITY lost on symlink import") {
				assert.Equal(t, uint32(444444), *sent.PreservedUIDValidity)
			}
			assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen, imap.Flag("$ExportSent")}, sent.Flags)
		}

		assert.NotContains(t, logs.String(), filepath.Join(realDir, "dovecot-keywords"),
			"INBOX dovecot-keywords was loaded as a subfolder keywords file")
	})
}
