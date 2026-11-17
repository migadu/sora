//go:build integration

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

const repairHeaderPresenceHelperEnv = "SORA_ADMIN_REPAIR_HEADER_PRESENCE_HELPER_ARGS"

// TestMessagesRepairHeaderPresenceCommandHelper runs "sora-admin messages <args>"
// through the real subcommand dispatcher in a subprocess, so an unknown
// subcommand (os.Exit(1)) surfaces as a failed run instead of killing the test.
func TestMessagesRepairHeaderPresenceCommandHelper(t *testing.T) {
	raw, ok := os.LookupEnv(repairHeaderPresenceHelperEnv)
	if !ok {
		t.Skip("helper process for runRepairHeaderPresenceCLI")
	}
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	os.Args = append([]string{"sora-admin", "messages"}, strings.Split(raw, "\n")...)
	handleMessagesCommand(context.Background())
}

func runRepairHeaderPresenceCLI(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMessagesRepairHeaderPresenceCommandHelper$")
	cmd.Env = append(os.Environ(), repairHeaderPresenceHelperEnv+"="+strings.Join(args, "\n"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	require.NoError(t, ctx.Err(), "messages command timed out: %s", stderr.String())
	t.Logf("messages %s (ok=%v, err=%v)\n%s", strings.Join(args, " "), err == nil, err, stdout.String())
	return stdout.String() + stderr.String(), err == nil
}

// Historical repair commands stay unavailable under the forward-only policy.
// The helper runs the real dispatcher, including its nonzero unknown-command exit.
func TestMessagesHistoricalRepairCommandsUnavailable(t *testing.T) {
	for _, command := range []string{"repair-header-presence", "repair-state"} {
		t.Run(command, func(t *testing.T) {
			out, ok := runRepairHeaderPresenceCLI(t, command, "--apply")
			require.False(t, ok)
			require.Contains(t, out, "Unknown messages subcommand: "+command)
		})
	}
}

// New ingress records presence; historical NULL rows retain the accepted legacy
// search behavior. Neither reads nor an attempted historical repair may fill them.
func TestMessagesHeaderPresenceRemainsForwardOnly(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	ctx := context.Background()

	conn, err := net.Dial("tcp", srv.Address)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(t, err)

	serial := 0
	command := func(line string, literal string) []string {
		t.Helper()
		serial++
		tag := fmt.Sprintf("t%d", serial)
		if literal != "" {
			_, err := fmt.Fprintf(conn, "%s %s {%d}\r\n", tag, line, len(literal))
			require.NoError(t, err)
			cont, err := r.ReadString('\n')
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(cont, "+"), "%s: %q", line, cont)
			_, err = fmt.Fprintf(conn, "%s\r\n", literal)
			require.NoError(t, err)
		} else {
			_, err := fmt.Fprintf(conn, "%s %s\r\n", tag, line)
			require.NoError(t, err)
		}
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
	search := func(criteria string) []int {
		t.Helper()
		got := []int{}
		for _, s := range command("UID SEARCH "+criteria, "") {
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

	command(fmt.Sprintf("LOGIN %q %q", account.Email, account.Password), "")
	// INBOX keeps known post-000070 masks, even for the same bodies as Legacy.
	command("APPEND INBOX", "From: a@example.com\r\nCc: c@example.com\r\nSubject: with cc\r\n\r\nbody 1\r\n")
	command("APPEND INBOX", "From: a@example.com\r\nSubject: without cc\r\n\r\nbody 2\r\n")
	command("CREATE Legacy", "")
	command("SELECT INBOX", "")
	command("UID COPY 1:2 Legacy", "")

	accountID, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	pool := srv.ResilientDB.GetOperationalDatabase().GetWritePool()

	// Make the Legacy rows look like pre-migration-000070 rows.
	var minID int64
	require.NoError(t, pool.QueryRow(ctx, `
		WITH legacy AS (
			UPDATE messages m SET header_presence = NULL
			FROM mailboxes mb
			WHERE mb.id = m.mailbox_id AND mb.account_id = $1 AND mb.name = 'Legacy'
			  AND m.expunged_at IS NULL
			RETURNING m.id)
		SELECT min(id) FROM legacy`, accountID).Scan(&minID))
	require.NotZero(t, minID)

	assertUnchangedMasks := func() {
		t.Helper()
		var unknown, known int
		require.NoError(t, pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE header_presence IS NULL),
			count(*) FILTER (WHERE header_presence IS NOT NULL)
			FROM messages WHERE account_id=$1 AND expunged_at IS NULL`, accountID).Scan(&unknown, &known))
		require.Equal(t, 2, unknown, "historical masks must stay NULL")
		require.Equal(t, 2, known, "new ingress masks must stay known")
	}
	cases := []struct {
		criteria string
		known    []int
		legacy   []int
	}{
		{`HEADER Cc ""`, []int{1}, []int{1, 2}},
		{`NOT HEADER Cc ""`, []int{2}, []int{}},
		{`CC ""`, []int{1}, []int{1, 2}},
		{`NOT CC ""`, []int{2}, []int{}},
		{`HEADER To ""`, []int{}, []int{1, 2}},
		{`NOT HEADER To ""`, []int{1, 2}, []int{}},
		{`TO ""`, []int{}, []int{1, 2}},
		{`NOT TO ""`, []int{1, 2}, []int{}},
		{`HEADER From ""`, []int{1, 2}, []int{1, 2}},
		{`NOT HEADER From ""`, []int{}, []int{}},
	}
	for _, apply := range []bool{false, true} {
		args := []string{"repair-header-presence", "--start-after", strconv.FormatInt(minID-1, 10)}
		if apply {
			args = append(args, "--apply")
		}
		out, ok := runRepairHeaderPresenceCLI(t, args...)
		require.False(t, ok)
		require.Contains(t, out, "Unknown messages subcommand: repair-header-presence")
		for _, mailbox := range []string{"INBOX", "Legacy"} {
			command("SELECT "+mailbox, "")
			for _, tc := range cases {
				want := tc.known
				if mailbox == "Legacy" {
					want = tc.legacy
				}
				require.Equal(t, want, search(tc.criteria), "mailbox=%s apply=%v criteria=%s", mailbox, apply, tc.criteria)
				assertUnchangedMasks()
			}
		}
	}
}
