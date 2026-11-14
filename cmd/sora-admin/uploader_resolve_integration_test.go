//go:build integration

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

// `uploader resolve` deletes the messages of a parked upload only on proof that the body
// is in neither S3 nor the spool. A spool directory that is not on this host is no such
// proof. With no [uploader] path in the config file, resolve used to look for the body
// relative to the directory it was run from, find nothing, and delete messages whose
// bodies were intact in the server's spool.
func TestResolveKeepsParkedUploadWithoutTheSpool(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uploads func(t *testing.T) string // the [uploader] section, empty for none
		deleted bool
	}{
		{"no uploader path", func(t *testing.T) string {
			if _, err := os.Stat(config.DefaultUploaderPath); err == nil {
				t.Skipf("the server's default spool %s exists on this host", config.DefaultUploaderPath)
			}
			return ""
		}, false},
		{"uploader path not on this host", func(t *testing.T) string {
			return fmt.Sprintf("[uploader]\npath = %q\n", filepath.Join(t.TempDir(), "missing"))
		}, false},
		// The spool is here and does not hold the body: the content is lost.
		{"body not in the spool here", func(t *testing.T) string {
			return fmt.Sprintf("[uploader]\npath = %q\n", t.TempDir())
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			uploads := tc.uploads(t)

			// config-test.toml is read relative to the package directory: open the
			// database before leaving it.
			rdb := openAdminTestDatabase(t)
			t.Cleanup(func() { rdb.Close() })
			endpoint := adminTestDBConfig(t).Write

			// Every object is missing from S3.
			s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			t.Cleanup(s3.Close)

			path := filepath.Join(t.TempDir(), "config.toml")
			content := fmt.Sprintf(`[database.write]
hosts = [%q]
port = %q
user = %q
password = %q
name = %q

[s3]
endpoint = %q
disable_tls = true
bucket = "resolve-test"
access_key = "test"
secret_key = "test"
`, endpoint.Hosts[0], fmt.Sprint(endpoint.Port), endpoint.User, endpoint.Password, endpoint.Name,
				strings.TrimPrefix(s3.URL, "http://")) + uploads
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			var cfg AdminConfig
			require.NoError(t, loadAdminConfig(path, &cfg))

			// A message of this host whose upload the uploader parked.
			email := fmt.Sprintf("resolve-%d@example.com", time.Now().UnixNano())
			accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
				Email: email, Password: "password123", IsPrimary: true, HashType: "bcrypt",
			})
			require.NoError(t, err)
			require.NoError(t, rdb.CreateDefaultMailboxesWithRetry(ctx, accountID))
			mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
			require.NoError(t, err)

			body := "Subject: parked\r\n\r\nparked body"
			hash := fmt.Sprintf("%064x", time.Now().UnixNano())
			var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
			_, _, err = rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
				AccountID:     accountID,
				MailboxID:     mailbox.ID,
				MailboxName:   "INBOX",
				S3Domain:      "example.com",
				S3Localpart:   strings.TrimSuffix(email, "@example.com"),
				ContentHash:   hash,
				MessageID:     fmt.Sprintf("<%s@example.com>", hash[48:]),
				InternalDate:  time.Now(),
				Size:          int64(len(body)),
				PlaintextBody: "parked body",
				BodyStructure: &bs,
			}, db.PendingUpload{InstanceID: cfg.InstanceID(), ContentHash: hash, Size: int64(len(body)), AccountID: accountID})
			require.NoError(t, err)
			_, err = rdb.ExecWithRetry(ctx, `UPDATE pending_uploads SET attempts = $3 WHERE account_id = $1 AND content_hash = $2`,
				accountID, hash, cfg.Uploader.MaxAttempts)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, _ = rdb.ExecWithRetry(context.Background(), `DELETE FROM pending_uploads WHERE account_id = $1`, accountID)
			})

			// Run from a directory that is not the spool.
			t.Chdir(t.TempDir())
			require.NoError(t, resolveFailedUploads(ctx, cfg, false, 100))

			var messages, pending int
			require.NoError(t, rdb.QueryRowWithRetry(ctx,
				`SELECT count(*) FROM messages WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&messages))
			require.NoError(t, rdb.QueryRowWithRetry(ctx,
				`SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&pending))
			if tc.deleted {
				require.Equal(t, 0, messages, "message of a body in neither S3 nor the spool %q", cfg.Uploader.Path)
				require.Equal(t, 0, pending, "parked upload of a body in neither S3 nor the spool %q", cfg.Uploader.Path)
				return
			}
			require.Equal(t, 1, messages, "resolve deleted the message although it could not see the spool %q", cfg.Uploader.Path)
			require.Equal(t, 1, pending, "resolve deleted the parked upload although it could not see the spool %q", cfg.Uploader.Path)
		})
	}
}
