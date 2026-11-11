//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestIMAP_CommandsPropagateSessionMasterPin runs each command in a session that has
// already written (and is therefore pinned to the master) while the read pool is a
// lagging replica: a second pool on the same server whose search_path starts with a
// shadow schema holding stale state. Every read the command makes must therefore go
// to the master; one that still reads the replica makes the command fail or answer
// from stale data.
func TestIMAP_CommandsPropagateSessionMasterPin(t *testing.T) {
	// Kinds of replica lag. Each names what the shadow schema overrides.
	var (
		lagMailboxes = []string{"mailboxes"}                                  // mailboxes created by the session are missing
		lagContents  = []string{"messages", "message_state", "mailbox_stats"} // mailbox contents are missing
	)

	cases := []struct {
		name string
		// setup runs against a healthy database, with INBOX (one message, UID 1)
		// selected and an empty mailbox PinDest created.
		setup func(c *rawIMAP)
		// emptyTables are shadowed by empty tables, snapshotTables by a copy taken
		// after setup, and staleRights makes every ACL check on the replica deny.
		emptyTables    []string
		snapshotTables []string
		staleRights    bool
		// cmds run in order against the lagging replica; all must complete OK and
		// the last one's response must contain want.
		cmds []string
		want string
	}{
		{name: "STATUS/mailbox lookup", emptyTables: lagMailboxes, cmds: []string{"STATUS PinDest (MESSAGES)"}, want: "MESSAGES 0"},
		{name: "STATUS/permission", staleRights: true, cmds: []string{"STATUS PinDest (MESSAGES)"}, want: "MESSAGES 0"},
		{name: "STATUS/summary", emptyTables: lagContents, cmds: []string{"STATUS INBOX (MESSAGES)"}, want: "MESSAGES 1"},

		{name: "DELETE/mailbox lookup", emptyTables: lagMailboxes, cmds: []string{"DELETE PinDest"}},
		{name: "DELETE/permission", staleRights: true, cmds: []string{"DELETE PinDest"}},
		{
			// The replica still shows the child the session has just deleted.
			name:           "DELETE/children",
			setup:          func(c *rawIMAP) { c.do("CREATE PinDest/Child") },
			snapshotTables: lagMailboxes,
			cmds:           []string{"DELETE PinDest/Child", "DELETE PinDest"},
		},

		{name: "COPY/mailbox lookup", emptyTables: lagMailboxes, cmds: []string{"UID COPY 1 PinDest"}, want: "COPYUID"},
		{name: "COPY/messages", emptyTables: lagContents, cmds: []string{"UID COPY 1 PinDest"}, want: "COPYUID"},

		{name: "MOVE/mailbox lookup", emptyTables: lagMailboxes, cmds: []string{"UID MOVE 1 PinDest"}, want: "COPYUID"},
		{name: "MOVE/rights", staleRights: true, cmds: []string{"UID MOVE 1 PinDest"}, want: "COPYUID"},
		{name: "MOVE/messages", emptyTables: lagContents, cmds: []string{"UID MOVE 1 PinDest"}, want: "COPYUID"},

		{name: "GETMETADATA/mailbox lookup", emptyTables: lagMailboxes, cmds: []string{"GETMETADATA PinDest /private/comment"}},
		{name: "GETMETADATA/permission", staleRights: true, cmds: []string{"GETMETADATA PinDest /private/comment"}},

		{name: "SETMETADATA/mailbox lookup", emptyTables: lagMailboxes, cmds: []string{`SETMETADATA PinDest (/private/comment "x")`}},
		{name: "SETMETADATA/permission", staleRights: true, cmds: []string{`SETMETADATA PinDest (/private/comment "x")`}},

		{name: "SEARCH", emptyTables: lagContents, cmds: []string{"UID SEARCH ALL"}, want: "* SEARCH 1"},
		{name: "SORT", emptyTables: lagContents, cmds: []string{"UID SORT (ARRIVAL) UTF-8 ALL"}, want: "* SORT 1"},

		{name: "FETCH/messages", emptyTables: lagContents, cmds: []string{"UID FETCH 1 (FLAGS)"}, want: "FETCH ("},
		{
			name: "FETCH/vanished",
			setup: func(c *rawIMAP) {
				c.appendMsg("INBOX", "Subject: second\r\n\r\nbody\r\n")
				c.do("ENABLE QRESYNC")
				c.do("SELECT INBOX")
				c.do(`UID STORE 2 +FLAGS (\Deleted)`)
				c.do("EXPUNGE")
			},
			emptyTables: lagContents,
			cmds:        []string{"UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)"},
			want:        "VANISHED (EARLIER) 2",
		},

		{
			name:        "EXPUNGE/permission",
			setup:       func(c *rawIMAP) { c.do(`UID STORE 1 +FLAGS (\Deleted)`) },
			staleRights: true,
			cmds:        []string{"EXPUNGE"},
			want:        "* 1 EXPUNGE",
		},
		{
			name:        "EXPUNGE/deleted messages",
			setup:       func(c *rawIMAP) { c.do(`UID STORE 1 +FLAGS (\Deleted)`) },
			emptyTables: lagContents,
			cmds:        []string{"EXPUNGE"},
			want:        "* 1 EXPUNGE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			c.appendMsg("INBOX", "Subject: pin\r\n\r\nbody\r\n") // a write: pins the session
			c.do("CREATE PinDest")
			c.do("SELECT INBOX")
			if tc.setup != nil {
				tc.setup(c)
			}

			defer installLaggingReplica(t, server, tc.emptyTables, tc.snapshotTables, tc.staleRights)()

			var response string
			for _, cmd := range tc.cmds {
				untagged, tagged := c.read(c.send(cmd), cmd)
				require.Containsf(t, tagged, " OK", "%s must read its own session's writes from the master, got: %s", cmd, tagged)
				response = strings.Join(append(untagged, tagged), "\n")
			}
			if tc.want != "" {
				require.Containsf(t, response, tc.want, "%s answered from the lagging replica", tc.cmds[len(tc.cmds)-1])
			}
		})
	}
}

// TestIMAP_FetchSeenRightPropagatesSessionMasterPin covers the one ACL read FETCH makes:
// a grantee of a shared mailbox needs the 's' right for a body FETCH to set \Seen.
func TestIMAP_FetchSeenRightPropagatesSessionMasterPin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	domain := owner.Email[strings.IndexByte(owner.Email, '@')+1:]
	granteeEmail, granteePassword := createSecondUser(t, server, domain, "fetchpin")

	shared := fmt.Sprintf("Shared/FetchPin-%d", common.GetTimestamp())
	co := dialRawIMAP(t, server.Address)
	co.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	co.do("CREATE " + shared)
	co.do(fmt.Sprintf("SETACL %s %s lrswi", shared, granteeEmail))

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", granteeEmail, granteePassword))
	c.appendMsg(shared, "Subject: pin\r\n\r\nbody\r\n") // a write: pins the session
	c.do("SELECT " + shared)

	defer installLaggingReplica(t, server, nil, nil, true)()

	c.do("UID FETCH 1 (BODY[])")
	untagged, _ := c.do("UID FETCH 1 (FLAGS)")
	require.Contains(t, strings.Join(untagged, "\n"), `\Seen`, "FETCH checked the 's' right on the lagging replica")
}

// installLaggingReplica swaps the server's read pool for a second pool on the same
// database whose search_path starts with a shadow schema: emptyTables are shadowed by
// empty tables, snapshotTables by a copy of their current rows, and staleRights makes
// every ACL check deny. The returned function restores the read pool.
func installLaggingReplica(t *testing.T, server *common.TestServer, emptyTables, snapshotTables []string, staleRights bool) (restore func()) {
	t.Helper()
	ctx := context.Background()
	database := server.ResilientDB.GetOperationalDatabase()
	schema := fmt.Sprintf("pin_cmd_replica_%d", time.Now().UnixNano())
	_, err := database.WritePool.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	for _, table := range emptyTables {
		_, err := database.WritePool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS SELECT * FROM public.%s WHERE false", schema, table, table))
		require.NoError(t, err)
	}
	for _, table := range snapshotTables {
		_, err := database.WritePool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS TABLE public.%s", schema, table, table))
		require.NoError(t, err)
	}
	if staleRights {
		_, err := database.WritePool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.has_mailbox_right(bigint, bigint, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'`, schema))
		require.NoError(t, err)
	}
	poolCfg := database.ReadPool.Config().Copy()
	poolCfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	lagging, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	original := database.ReadPool
	database.ReadPool = lagging
	return func() {
		database.ReadPool = original
		lagging.Close()
		_, _ = database.WritePool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	}
}
