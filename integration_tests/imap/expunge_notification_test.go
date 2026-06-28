//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// These tests guard against the "Apple Mail disappearing/blank message" bug:
// deleting a message caused the server to emit the EXPUNGE notification multiple
// times (plus a spurious EXISTS), which made adjacent messages momentarily vanish
// and left blank phantom rows until the client resynced. Each delete must emit
// exactly one EXPUNGE per removed message and no phantom EXISTS — both to the
// issuing connection and to other connections watching the same mailbox (which is
// how Apple Mail is structured: a dedicated IDLE connection renders the list).

// rawConn is a tiny raw IMAP client for counting untagged responses.
type rawConn struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dialRaw(t *testing.T, addr string) *rawConn {
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	rc := &rawConn{t: t, conn: conn, r: bufio.NewReader(conn)}
	greeting, err := rc.r.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, greeting, "OK")
	return rc
}

// cmd sends a command and reads until the tagged response, returning all
// untagged ("* ...") lines and the final tagged line.
func (rc *rawConn) cmd(tag, command string) (untagged []string, tagged string) {
	_, err := rc.conn.Write([]byte(tag + " " + command + "\r\n"))
	require.NoError(rc.t, err)
	for {
		line, err := rc.r.ReadString('\n')
		require.NoError(rc.t, err)
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return untagged, line
		}
		if strings.HasPrefix(line, "* ") {
			untagged = append(untagged, line)
		}
	}
}

func (rc *rawConn) login(account common.TestAccount) {
	_, tagged := rc.cmd("L", fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	require.Contains(rc.t, tagged, "OK")
}

// append uses a synchronizing literal.
func (rc *rawConn) append(tag, mailbox, body string) {
	_, err := rc.conn.Write([]byte(fmt.Sprintf("%s APPEND %s {%d}\r\n", tag, mailbox, len(body))))
	require.NoError(rc.t, err)
	cont, err := rc.r.ReadString('\n')
	require.NoError(rc.t, err)
	require.True(rc.t, strings.HasPrefix(cont, "+"), "expected continuation, got %q", cont)
	_, err = rc.conn.Write([]byte(body + "\r\n"))
	require.NoError(rc.t, err)
	for {
		line, err := rc.r.ReadString('\n')
		require.NoError(rc.t, err)
		if strings.HasPrefix(line, tag+" ") {
			require.Contains(rc.t, line, "OK", "APPEND failed: %s", line)
			return
		}
	}
}

func expungeSeqs(untagged []string) []string {
	var seqs []string
	for _, l := range untagged {
		parts := strings.Fields(l)
		if len(parts) >= 3 && parts[0] == "*" && strings.ToUpper(parts[2]) == "EXPUNGE" {
			seqs = append(seqs, parts[1])
		}
	}
	return seqs
}

func existsCount(untagged []string) int {
	n := 0
	for _, l := range untagged {
		parts := strings.Fields(l)
		if len(parts) >= 3 && parts[0] == "*" && strings.ToUpper(parts[2]) == "EXISTS" {
			n++
		}
	}
	return n
}

func msg(i int) string {
	return fmt.Sprintf("From: test@example.com\r\nTo: user@example.com\r\nSubject: Msg %d\r\n\r\nBody %d\r\n", i, i)
}

func setupInboxWith(t *testing.T, rc *rawConn, n int) {
	for i := 1; i <= n; i++ {
		rc.append(fmt.Sprintf("ap%d", i), "INBOX", msg(i))
	}
	_, tagged := rc.cmd("sel", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
}

// TestAppleMail_ExpungeSingleNotify: deleting one message emits exactly one
// EXPUNGE and no EXISTS on the issuing connection.
func TestAppleMail_ExpungeSingleNotify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)
	setupInboxWith(t, rc, 5)

	_, tagged := rc.cmd("s", "STORE 3 +FLAGS (\\Deleted)")
	require.Contains(t, tagged, "OK")

	untagged, tagged := rc.cmd("e", "EXPUNGE")
	require.Contains(t, tagged, "OK")
	t.Logf("EXPUNGE untagged (%d): %v", len(untagged), untagged)

	require.Equal(t, []string{"3"}, expungeSeqs(untagged),
		"expected exactly one '* 3 EXPUNGE' (duplicates corrupt the client seqnum map)")
	require.Equal(t, 0, existsCount(untagged), "no phantom EXISTS expected after expunge")
}

// TestAppleMail_ExpungeMultipleNotify: deleting several messages in one EXPUNGE
// emits one EXPUNGE per message, highest sequence first, with no duplicates and
// no phantom EXISTS.
func TestAppleMail_ExpungeMultipleNotify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)
	setupInboxWith(t, rc, 6)

	// Mark 2,3,4 deleted (a contiguous middle run, like selecting a range).
	_, tagged := rc.cmd("s", "STORE 2:4 +FLAGS (\\Deleted)")
	require.Contains(t, tagged, "OK")

	untagged, tagged := rc.cmd("e", "EXPUNGE")
	require.Contains(t, tagged, "OK")
	t.Logf("EXPUNGE untagged (%d): %v", len(untagged), untagged)

	// Highest-first so each sequence number is valid as the client applies them.
	require.Equal(t, []string{"4", "3", "2"}, expungeSeqs(untagged),
		"expected '* 4/3/2 EXPUNGE' once each, descending")
	require.Equal(t, 0, existsCount(untagged), "no phantom EXISTS expected after expunge")
}

// TestAppleMail_UIDExpungeSingleNotify: same guard for the UID EXPUNGE path.
func TestAppleMail_UIDExpungeSingleNotify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)
	setupInboxWith(t, rc, 5)

	_, tagged := rc.cmd("s", "STORE 3 +FLAGS (\\Deleted)")
	require.Contains(t, tagged, "OK")

	// UID of seq 3 is 3 here (fresh mailbox, UIDs 1..5).
	untagged, tagged := rc.cmd("e", "UID EXPUNGE 3")
	require.Contains(t, tagged, "OK")
	t.Logf("UID EXPUNGE untagged (%d): %v", len(untagged), untagged)

	require.Equal(t, []string{"3"}, expungeSeqs(untagged))
	require.Equal(t, 0, existsCount(untagged))
}

// TestAppleMail_ExpungeCrossSessionViewer reproduces the real Apple Mail
// topology: one connection renders the message list while another deletes a
// message. The viewer discovers the change on its next poll (here triggered
// deterministically via NOOP) and must receive exactly one EXPUNGE and no
// phantom EXISTS.
func TestAppleMail_ExpungeCrossSessionViewer(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connection A: the "viewer".
	a := dialRaw(t, server.Address)
	defer a.conn.Close()
	a.login(account)
	setupInboxWith(t, a, 5)

	// Connection B: the "actor" that deletes.
	b := dialRaw(t, server.Address)
	defer b.conn.Close()
	b.login(account)
	_, tagged := b.cmd("bsel", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = b.cmd("bs", "STORE 3 +FLAGS (\\Deleted)")
	require.Contains(t, tagged, "OK")

	// B expunges; it should get exactly one EXPUNGE itself.
	bUntagged, tagged := b.cmd("be", "EXPUNGE")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"3"}, expungeSeqs(bUntagged), "actor connection got wrong EXPUNGEs")
	require.Equal(t, 0, existsCount(bUntagged))

	// A polls (NOOP) and must see exactly one EXPUNGE and no phantom EXISTS.
	aUntagged, tagged := a.cmd("an", "NOOP")
	require.Contains(t, tagged, "OK")
	t.Logf("viewer NOOP untagged (%d): %v", len(aUntagged), aUntagged)

	require.Equal(t, []string{"3"}, expungeSeqs(aUntagged),
		"the viewer connection must receive exactly one '* 3 EXPUNGE'")
	require.Equal(t, 0, existsCount(aUntagged), "the viewer must not receive a phantom EXISTS")
}

// TestAppleMail_MoveSingleNotify is the reference: MOVE already behaved correctly
// (one EXPUNGE, no phantom EXISTS). Kept as a guard so EXPUNGE stays aligned.
func TestAppleMail_MoveSingleNotify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)
	setupInboxWith(t, rc, 5) // Trash exists by default (consts.DefaultMailboxes)

	untagged, tagged := rc.cmd("m", "MOVE 3 Trash")
	require.Contains(t, tagged, "OK")
	t.Logf("MOVE untagged (%d): %v", len(untagged), untagged)

	require.Equal(t, []string{"3"}, expungeSeqs(untagged))
	require.Equal(t, 0, existsCount(untagged))
}
