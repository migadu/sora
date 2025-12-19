//go:build integration

package imap_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_MaildirImport_UIDStability imports testdata/Maildir using sora-admin importer
// with UID preservation enabled, then verifies via IMAP:
//  1. UIDVALIDITY matches dovecot-uidlist header for INBOX
//  2. UIDNEXT matches NextUID from dovecot-uidlist header
//  3. UIDs for a sample of messages match dovecot-uidlist mappings
//  4. No message has persistent \\Recent flag after import
//
// This is an end-to-end regression test for the "clients redownload everything after import" symptom.
func TestIMAP_MaildirImport_UIDStability(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	ctx := context.Background()

	// Setup server + DB
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()

	// Create account with a deterministic email (importer needs it)
	testEmail := fmt.Sprintf("import-e2e-%d@example.com", time.Now().UnixNano())
	account = common.CreateTestAccountWithEmail(t, srv.ResilientDB, testEmail, account.Password)

	// Copy testdata/Maildir to a temp dir because importer writes sora-maildir.db into the maildir
	tmp := t.TempDir()
	maildirPath := filepath.Join(tmp, "Maildir")
	if err := copyDir(filepath.Join("..", "..", "testdata", "Maildir"), maildirPath); err != nil {
		t.Fatalf("copy test maildir: %v", err)
	}

	// Parse expected dovecot state (header from dovecot-uidlist)
	uidValidity, nextUID, uidMappings, err := parseDovecotUIDListForTest(maildirPath)
	if err != nil {
		t.Fatalf("parseDovecotUIDListForTest: %v", err)
	}

	// Run sora-admin import against this account.
	// We run it with --cleanup-db so it doesn't leave sora-maildir.db behind.
	// NOTE: The integration test DB config must be compatible with cmd/sora-admin --config usage.
	if err := runSoraAdminImportMaildir(ctx, testEmail, maildirPath); err != nil {
		t.Fatalf("sora-admin import failed: %v", err)
	}

	// Connect via IMAP and verify SELECT values
	c, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("failed to connect to IMAP: %v", err)
	}
	defer c.Close()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("LOGIN failed: %v", err)
	}

	mbox, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	if mbox.UIDValidity != uidValidity {
		t.Fatalf("UIDVALIDITY mismatch: imap=%d dovecot=%d", mbox.UIDValidity, uidValidity)
	}
	if uint32(mbox.UIDNext) != nextUID {
		t.Fatalf("UIDNEXT mismatch: imap=%d dovecotNext=%d", mbox.UIDNext, nextUID)
	}

	// Fetch UIDs + FLAGS for first N messages and check:
	// - UID exists in dovecot-uidlist mapping
	// - \\Recent is not present
	const maxCheck = 25
	seqEnd := uint32(mbox.NumMessages)
	if seqEnd > maxCheck {
		seqEnd = maxCheck
	}
	if seqEnd == 0 {
		t.Fatalf("expected non-empty INBOX after import")
	}

	fetchCmd := c.Fetch(imap.SeqSetNum(1, seqEnd), &imap.FetchOptions{UID: true, Flags: true})
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if err := fetchCmd.Close(); err != nil {
		t.Fatalf("FETCH close failed: %v", err)
	}

	for _, m := range msgs {
		if m.UID == 0 {
			t.Fatalf("message with zero UID returned")
		}

		// UID must be in uidlist mapping values.
		// We do a linear scan over uidlist for the small sample.
		found := false
		for _, u := range uidMappings {
			if uint32(m.UID) == u {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("imported UID %d not found in dovecot-uidlist mappings (sample check)", m.UID)
		}

		for _, f := range m.Flags {
			if string(f) == "\\Recent" {
				t.Fatalf("\\Recent flag was persisted on UID=%d", m.UID)
			}
		}
	}
}

func runSoraAdminImportMaildir(ctx context.Context, email, maildirPath string) error {
	cmd := exec.CommandContext(ctx, "../../integration_tests/sora-admin",
		"--config", "../../config-test.toml",
		"import", "maildir",
		"--email", email,
		"--maildir-path", maildirPath,
		"--dovecot",
		"--cleanup-db",
		"--batch-size", "25",
		"--jobs", "4",
	)
	cmd.Env = append(os.Environ(),
		"SORA_ADMIN_SKIP_S3=1",
		"SORA_TEST_DB_NAME=sora_test_db",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sora-admin import maildir failed: %w\noutput:\n%s", err, string(out))
	}
	return nil
}

func parseDovecotUIDListForTest(maildirPath string) (uidValidity uint32, nextUID uint32, uids []uint32, err error) {
	f, err := os.Open(filepath.Join(maildirPath, "dovecot-uidlist"))
	if err != nil {
		return 0, 0, nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	if !s.Scan() {
		return 0, 0, nil, fmt.Errorf("empty dovecot-uidlist")
	}

	// Header format: "3 V<uidvalidity> N<nextuid> ..."
	header := s.Text()
	for _, field := range strings.Fields(header) {
		if strings.HasPrefix(field, "V") {
			v, perr := strconv.ParseUint(strings.TrimPrefix(field, "V"), 10, 64)
			if perr != nil {
				return 0, 0, nil, perr
			}
			uidValidity = uint32(v)
		}
		if strings.HasPrefix(field, "N") {
			n, perr := strconv.ParseUint(strings.TrimPrefix(field, "N"), 10, 64)
			if perr != nil {
				return 0, 0, nil, perr
			}
			nextUID = uint32(n)
		}
	}
	if uidValidity == 0 || nextUID == 0 {
		return 0, 0, nil, fmt.Errorf("missing V/N in header: %q", header)
	}

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		// Mapping lines start with UID
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		uid64, perr := strconv.ParseUint(parts[0], 10, 32)
		if perr != nil {
			continue
		}
		uids = append(uids, uint32(uid64))
	}
	if err := s.Err(); err != nil {
		return 0, 0, nil, err
	}
	if len(uids) == 0 {
		return 0, 0, nil, fmt.Errorf("no UID mappings found in dovecot-uidlist")
	}
	return uidValidity, nextUID, uids, nil
}

// copyDir recursively copies src to dst.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		outPath := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(outPath, info.Mode())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Ensure we preserve bytes as-is (some messages may not be valid UTF-8)
		return os.WriteFile(outPath, bytes.Clone(b), info.Mode())
	})
}
