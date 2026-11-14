//go:build integration

package imap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAppend_StagingErrorHidesSpoolPath: when APPEND cannot stage the body in this node's
// spool, the NO [SERVERBUG] response carries the cause only. The spool path, which names
// the account id and the content hash, goes to the session log (issue #797).
func TestAppend_StagingErrorHidesSpoolPath(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	literal := "From: sender@example.com\r\nTo: user@example.com\r\nSubject: Staging error\r\n\r\n" +
		strings.Repeat("The spool cannot take this body.\r\n", 8)
	hash := helpers.HashContent([]byte(literal))

	cases := []struct {
		name string
		// obstruct breaks the account's spool directory accountDir.
		obstruct func(t *testing.T, accountDir string)
		want     string
	}{
		{
			// The existence check before staging fails (*fs.PathError from os.Stat).
			name: "stat",
			obstruct: func(t *testing.T, accountDir string) {
				require.NoError(t, os.WriteFile(accountDir, []byte("not a directory"), 0600))
			},
			want: "failed to check file existence: ",
		},
		{
			// Creating the spool directory fails (*fs.PathError from os.MkdirAll).
			name: "mkdir",
			obstruct: func(t *testing.T, accountDir string) {
				require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing"), accountDir))
			},
			want: "failed to save message to disk: ",
		},
		{
			// Moving the staged file into place fails (*os.LinkError from os.Rename).
			name: "rename",
			obstruct: func(t *testing.T, accountDir string) {
				target := filepath.Join(accountDir, hash)
				require.NoError(t, os.MkdirAll(target, 0755))
				info, err := os.Stat(target)
				require.NoError(t, err)
				require.NotEqual(t, int64(len(literal)), info.Size(), "the obstruction must not look like a staged body")
			},
			want: "failed to save message to disk: ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, account := common.SetupIMAPServer(t)
			defer server.Close()

			accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
			require.NoError(t, err)
			accountDir := filepath.Join(server.UploadPath, strconv.FormatInt(accountID, 10))
			tc.obstruct(t, accountDir)

			c, err := imapclient.DialInsecure(server.Address, nil)
			require.NoError(t, err)
			defer c.Logout()
			require.NoError(t, c.Login(account.Email, account.Password).Wait())

			cmd := c.Append("INBOX", int64(len(literal)), nil)
			_, err = cmd.Write([]byte(literal))
			require.NoError(t, err)
			require.NoError(t, cmd.Close())
			_, err = cmd.Wait()

			var imapErr *imap.Error
			require.True(t, errors.As(err, &imapErr), "APPEND with a broken spool: got %v, want NO [SERVERBUG]", err)
			assert.Equal(t, imap.StatusResponseTypeNo, imapErr.Type)
			assert.Equal(t, imap.ResponseCodeServerBug, imapErr.Code, "response %q", imapErr.Text)
			assert.True(t, strings.HasPrefix(imapErr.Text, tc.want), "response %q, want prefix %q", imapErr.Text, tc.want)
			assert.NotContains(t, imapErr.Text, server.UploadPath, "the response must not name the spool path")
			assert.NotContains(t, imapErr.Text, hash, "the response must not name the staged file")
		})
	}
}
