//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_AppendOverNestedMimeRemainsFetchable(t *testing.T) {
	b, account := common.SetupIMAPServer(t)
	defer b.Close()
	c, err := imapclient.DialInsecure(b.Address, nil)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())
	_, err = c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	for _, attached := range []bool{false, true} {
		name := "plain"
		if attached {
			name = "hidden attachment"
		}
		t.Run(name, func(t *testing.T) {
			uid := appendRaw(t, c, "INBOX", "Subject: deep MIME\r\n"+common.NestedAttachmentMIME(256, attached), nil)
			messages, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
				BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
			}).Collect()
			require.NoError(t, err, "the classification budget must not reject or break FETCH")
			require.Len(t, messages, 1)
			require.NotNil(t, messages[0].BodyStructure)
			flags := fetchFlags(t, c, uid)
			require.NotContains(t, flags, imap.Flag("$hasattachment"))
			require.NotContains(t, flags, imap.Flag("$hasnoattachment"))
		})
	}
}
