//go:build integration

package lmtp_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// TestLMTP_StagingErrorHidesSpoolPath: when a delivery cannot stage the body in this
// node's spool, the 451 reply carries the cause only. The spool path, which names the
// account id and the content hash, goes to the session log: the reply text reaches the
// MTA and can end up in a delay or bounce notice to the sender (issue #797).
func TestLMTP_StagingErrorHidesSpoolPath(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	cases := []struct {
		name string
		// obstruct breaks the account's spool directory accountDir.
		obstruct func(t *testing.T, accountDir string)
		want     string
	}{
		{
			name: "permission",
			obstruct: func(t *testing.T, accountDir string) {
				if os.Geteuid() == 0 {
					t.Skip("root bypasses directory permissions")
				}
				if err := os.MkdirAll(accountDir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(accountDir, 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(accountDir, 0755) })
			},
			want: "failed to check file existence: ",
		},
		{
			// The existence check before staging fails (*fs.PathError from os.Stat).
			name: "stat",
			obstruct: func(t *testing.T, accountDir string) {
				if err := os.WriteFile(accountDir, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			},
			want: "failed to check file existence: ",
		},
		{
			// Creating the spool directory fails (*fs.PathError from os.MkdirAll).
			name: "mkdir",
			obstruct: func(t *testing.T, accountDir string) {
				if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), accountDir); err != nil {
					t.Fatal(err)
				}
			},
			want: "failed to save message to disk: ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rdb := common.SetupTestDatabase(t)
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
			if err != nil {
				t.Fatal(err)
			}
			addr, up := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{})
			accountDir := filepath.Dir(up.FilePath(strings.Repeat("0", 64), accountID))
			spoolRoot := filepath.Dir(accountDir)
			tc.obstruct(t, accountDir)

			msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: Staging error\r\n" +
				"Message-ID: <staging-error-" + tc.name + "@example.com>\r\n\r\nbody\r\n"
			resp := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, msg)
			if !strings.HasPrefix(resp, "451 4.3.0 ") || !strings.Contains(resp, tc.want) {
				t.Fatalf("reply %q, want 451 4.3.0 with %q", resp, tc.want)
			}
			if strings.Contains(resp, spoolRoot) {
				t.Errorf("reply names the spool path %s: %q", spoolRoot, resp)
			}
		})
	}
}
