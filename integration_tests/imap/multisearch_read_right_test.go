//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readRightTracer records the mailboxes whose rights a server checks for one
// account with a CheckMailboxPermission round trip (SELECT has_mailbox_right(...)).
type readRightTracer struct {
	mu        sync.Mutex
	accountID int64
	checked   []int64
}

func (r *readRightTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if !strings.HasPrefix(strings.TrimSpace(q.SQL), "SELECT has_mailbox_right(") || len(q.Args) != 3 {
		return ctx
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := q.Args[0].(int64); ok && q.Args[1] == r.accountID {
		r.checked = append(r.checked, id)
	}
	return ctx
}

func (r *readRightTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// watch starts recording the checks for accountID, forgetting earlier ones.
func (r *readRightTracer) watch(accountID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accountID, r.checked = accountID, nil
}

func (r *readRightTracer) checks() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.checked)
}

// TestIMAP_MultiSearchChecksReadRightOnlyOnOthersMailboxes is the regression test
// for #1787: ESEARCH IN (...) ran a has_mailbox_right round trip for every mailbox
// in scope before searching it, so each of the user's own mailboxes cost two
// queries. has_mailbox_right returns TRUE for the owner as its first step; only a
// mailbox another account shares with the user can lack the 'r' right that RFC 7377
// §2.2 requires, and only there may the check change the outcome.
func TestIMAP_MultiSearchChecksReadRightOnlyOnOthersMailboxes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	reader, readerPassword := createSecondUser(t, server, "example.com", "msright")
	ownerID, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(ctx, owner.Email)
	require.NoError(t, err)
	readerID, err := server.ResilientDB.GetActiveAccountIDByAddressWithRetry(ctx, reader)
	require.NoError(t, err)

	ts := common.GetTimestamp()
	personal := []string{"INBOX", fmt.Sprintf("MSRight-%d-1", ts), fmt.Sprintf("MSRight-%d-2", ts), fmt.Sprintf("MSRight-%d-3", ts)}
	prefix := fmt.Sprintf("Shared/MSRight-%d", ts)
	readable, lookupOnly := prefix+"/Readable", prefix+"/Lookup"
	msg := "From: sender@example.com\r\nSubject: msright\r\n\r\nbody\r\n"

	o := dialRawIMAP(t, server.Address)
	o.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	for _, name := range append(slices.Clone(personal), readable, lookupOnly) {
		if name != "INBOX" {
			o.do("CREATE " + esearchQuote(name))
		}
		o.appendMsg(esearchQuote(name), msg)
	}
	o.do("SETACL " + esearchQuote(readable) + " " + esearchQuote(reader) + " lr")
	o.do("SETACL " + esearchQuote(lookupOnly) + " " + esearchQuote(reader) + " l")
	r := dialRawIMAP(t, server.Address)
	r.do(fmt.Sprintf("LOGIN %s %s", reader, readerPassword))
	r.appendMsg("INBOX", msg)

	mailboxID := func(name string) int64 {
		m, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, name)
		require.NoError(t, err)
		return m.ID
	}
	readableID, lookupOnlyID := mailboxID(readable), mailboxID(lookupOnly)

	tracer := &readRightTracer{}
	addr := startACLPermissionGateServer(t, server.ResilientDB, tracer)
	counts := func(lines []string) map[string]string {
		t.Helper()
		out := map[string]string{}
		for name := range esearchMailboxes(t, lines) {
			_, count, _ := strings.Cut(esearchLine(lines, name), " COUNT ")
			out[name] = count
		}
		return out
	}

	t.Run("own mailboxes", func(t *testing.T) {
		c := dialRawIMAP(t, addr)
		c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
		tracer.watch(ownerID)
		lines, _ := c.do("ESEARCH IN (PERSONAL SUBTREE " + esearchQuote(prefix) + ") RETURN (COUNT) ALL")
		got := counts(lines)
		for _, name := range append(slices.Clone(personal), readable, lookupOnly) {
			assert.Equalf(t, "1", got[name], "%s: the owner searches every mailbox it owns, shared ones too (%q)", name, lines)
		}
		assert.Empty(t, tracer.checks(), "the owner has every right on its own mailboxes: no has_mailbox_right round trip is needed for them")
	})

	t.Run("mailboxes shared with the user", func(t *testing.T) {
		c := dialRawIMAP(t, addr)
		c.do(fmt.Sprintf("LOGIN %s %s", reader, readerPassword))
		tracer.watch(readerID)
		lines, _ := c.do("ESEARCH IN (PERSONAL MAILBOXES (" + esearchQuote(readable) + " " + esearchQuote(lookupOnly) + ")) RETURN (COUNT) ALL")
		got := counts(lines)
		assert.Equal(t, "1", got["INBOX"], "%q", lines)
		assert.Equal(t, "1", got[readable], "%q", lines)
		assert.NotContains(t, got, lookupOnly, "RFC 7377 §2.2: a mailbox the user lacks the 'r' right on is ignored")
		assert.ElementsMatch(t, []int64{readableID, lookupOnlyID}, tracer.checks(),
			"one read-right check for each mailbox another account shares with the user, none for the user's own")
	})
}
