//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestIMAP_HeaderPresenceHistoricalRepair verifies that pre-migration-000070 rows
// (header_presence IS NULL) repaired via FindNullHeaderPresence + FillNullHeaderPresence
// (from DB donors and raw header bytes) stop matching absent headers on
// UID SEARCH HEADER From/To/Cc "" and FROM/TO/CC "".
func TestIMAP_HeaderPresenceHistoricalRepair(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	ctx := context.Background()

	c, err := imapclient.DialInsecure(srv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, c.Login(account.Email, account.Password).Wait())

	raws := []string{
		// UID 1: empty group on From/To/Cc
		"From: undisclosed:;\r\nTo: undisclosed:;\r\nCc: undisclosed:;\r\n\r\ngroup\r\n",
		// UID 2: present-empty From/To/Cc
		"From:\r\nTo:\r\nCc:\r\n\r\nempty\r\n",
		// UID 3: absent From/To/Cc
		"Subject: absent addresses\r\n\r\nabsent\r\n",
		// UID 4: populated From/To/Cc
		"From: a@example.com\r\nTo: b@example.com\r\nCc: c@example.com\r\n\r\nvalid\r\n",
	}
	for _, raw := range raws {
		cmd := c.Append("INBOX", int64(len(raw)), nil)
		_, err := cmd.Write([]byte(raw))
		require.NoError(t, err)
		require.NoError(t, cmd.Close())
		_, err = cmd.Wait()
		require.NoError(t, err)
	}
	require.NoError(t, c.Logout().Wait())
	c.Close()

	accountID, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	pool := srv.ResilientDB.GetOperationalDatabase().GetWritePool()

	// Simulate pre-000070 rows: clear header_presence to NULL on all 4 rows.
	var ids []int64
	rows, err := pool.Query(ctx, `SELECT id FROM messages WHERE account_id = $1 AND expunged_at IS NULL ORDER BY uid`, accountID)
	require.NoError(t, err)
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	require.Len(t, ids, 4)

	_, err = pool.Exec(ctx, `UPDATE messages SET header_presence = NULL WHERE id = ANY($1)`, ids)
	require.NoError(t, err)

	// Run repair batch across our test rows using raw header extraction (as --from-s3 does).
	batch, err := srv.ResilientDB.FindNullHeaderPresenceWithRetry(ctx, ids[0]-1, 100)
	require.NoError(t, err)
	var fills []db.HeaderPresenceFill
	for i, id := range ids {
		mask := helpers.ExtractRawHeaderPresence([]byte(raws[i]))
		require.NotNil(t, mask)
		fills = append(fills, db.HeaderPresenceFill{ID: id, HeaderPresence: *mask})
	}
	require.GreaterOrEqual(t, len(batch.NeedsS3)+len(batch.Fills), 4)
	n, err := srv.ResilientDB.FillNullHeaderPresenceWithRetry(ctx, fills)
	require.NoError(t, err)
	require.Equal(t, int64(4), n)

	conn, err := net.Dial("tcp", srv.Address)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(t, err)

	command := func(tag, line string) []string {
		t.Helper()
		_, err := fmt.Fprintf(conn, "%s %s\r\n", tag, line)
		require.NoError(t, err)
		var out []string
		for {
			s, err := r.ReadString('\n')
			require.NoError(t, err)
			s = strings.TrimSpace(s)
			out = append(out, s)
			if strings.HasPrefix(s, tag+" ") {
				require.True(t, strings.HasPrefix(s, tag+" OK"), "%s: %v", line, out)
				return out
			}
		}
	}
	command("l", fmt.Sprintf("LOGIN %q %q", account.Email, account.Password))
	command("s", "SELECT INBOX")

	serial := 0
	search := func(line string) []int {
		t.Helper()
		serial++
		lines := command(fmt.Sprintf("q%d", serial), "UID SEARCH "+line)
		got := []int{}
		for _, s := range lines {
			if strings.HasPrefix(s, "* SEARCH") {
				for _, tok := range strings.Fields(strings.TrimPrefix(s, "* SEARCH")) {
					u, err := strconv.Atoi(tok)
					require.NoError(t, err)
					got = append(got, u)
				}
			}
		}
		slices.Sort(got)
		return got
	}

	for _, key := range []string{"From", "To", "Cc"} {
		require.Equal(t, []int{1, 2, 4}, search("HEADER "+key+` ""`), "HEADER %s", key)
		require.Equal(t, []int{3}, search("NOT HEADER "+key+` ""`), "NOT HEADER %s", key)
		require.Equal(t, []int{4}, search(strings.ToUpper(key)+` ""`), "%s shorthand", key)
		require.Equal(t, []int{1, 2, 3}, search("NOT "+strings.ToUpper(key)+` ""`), "NOT %s shorthand", key)
	}
}
