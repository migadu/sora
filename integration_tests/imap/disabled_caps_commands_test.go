//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_DisabledCapsRefusesCommands: a capability withdrawn by disabled_caps
// or client_filters must not only leave CAPABILITY but also refuse its commands,
// as IDLE and ESEARCH already were. MOVE, NAMESPACE, STATUS=SIZE, METADATA and
// SORT kept working, and SORT=DISPLAY and ESORT stayed advertised without SORT
// (#508).
func TestIMAP_DisabledCapsRefusesCommands(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	disabled := []string{"MOVE", "NAMESPACE", "STATUS=SIZE", "METADATA", "SORT"}

	for _, tc := range []struct {
		name      string
		configure func(*imapserver.IMAPServerOptions)
		identify  bool
	}{
		{"disabled_caps", func(o *imapserver.IMAPServerOptions) { o.DisabledCaps = disabled }, false},
		{"client_filters", func(o *imapserver.IMAPServerOptions) {
			o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: disabled}}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dialDisabledCaps(t, tc.configure, tc.identify)
			do, mustOK, wantBad := c.do, c.mustOK, c.wantBad

			capLine, _, _ := strings.Cut(do("CAPABILITY"), "\r\n")
			caps := strings.Fields(capLine)
			for _, c := range []string{"IMAP4rev2", "MOVE", "NAMESPACE", "STATUS=SIZE", "METADATA", "SORT", "SORT=DISPLAY", "ESORT"} {
				if slices.Contains(caps, c) {
					t.Errorf("CAPABILITY still offers %s:\n%s", c, capLine)
				}
			}
			for _, c := range []string{"IMAP4rev1", "LIST-STATUS", "UIDPLUS"} {
				if !slices.Contains(caps, c) {
					t.Errorf("CAPABILITY lost %s:\n%s", c, capLine)
				}
			}

			c.appendMessage()
			mustOK("CREATE Moved")

			wantBad("NAMESPACE")
			wantBad("STATUS INBOX (SIZE)")
			wantBad(`LIST "" "INBOX" RETURN (STATUS (MESSAGES SIZE))`)
			wantBad(`GETMETADATA "" /shared/comment`)
			wantBad(`SETMETADATA "" (/private/comment "x")`)
			if resp := mustOK("STATUS INBOX (MESSAGES)"); !strings.Contains(resp, "MESSAGES 1") {
				t.Errorf("STATUS INBOX (MESSAGES): want MESSAGES 1, got:\n%s", resp)
			}

			mustOK("SELECT INBOX")
			wantBad("SORT (DATE) UTF-8 ALL")
			wantBad("UID SORT (DATE) UTF-8 ALL")
			wantBad("SORT RETURN (ALL) (DATE) UTF-8 ALL")
			wantBad("MOVE 1 Moved")
			wantBad("UID MOVE 1:* Moved")
			mustOK("UNSELECT")

			if resp := mustOK("STATUS Moved (MESSAGES)"); !strings.Contains(resp, "MESSAGES 0") {
				t.Errorf("a refused MOVE moved a message:\n%s", resp)
			}
		})
	}
}

// TestIMAP_DisabledCapsRefusesListThreadAndUIDPlus: the steps of #578. THREAD=*,
// MULTISEARCH, UIDPLUS, CREATE-SPECIAL-USE, LIST-EXTENDED and SPECIAL-USE left
// CAPABILITY but ESEARCH, THREAD, UID EXPUNGE, CREATE ... (USE ...) and the
// LIST-EXTENDED options kept working. What stays in IMAP4rev1 (LSUB, a plain
// LIST, EXPUNGE, CREATE) must not be refused with them.
func TestIMAP_DisabledCapsRefusesListThreadAndUIDPlus(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	disabled := []string{"THREAD=REFERENCES", "THREAD=REFS", "THREAD=ORDEREDSUBJECT", "MULTISEARCH", "UIDPLUS", "CREATE-SPECIAL-USE", "LIST-EXTENDED", "SPECIAL-USE"}

	for _, tc := range []struct {
		name      string
		configure func(*imapserver.IMAPServerOptions)
		identify  bool
	}{
		{"disabled_caps", func(o *imapserver.IMAPServerOptions) { o.DisabledCaps = disabled }, false},
		{"client_filters", func(o *imapserver.IMAPServerOptions) {
			o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: disabled}}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dialDisabledCaps(t, tc.configure, tc.identify)

			capLine, _, _ := strings.Cut(c.do("CAPABILITY"), "\r\n")
			caps := strings.Fields(capLine)
			for _, name := range append([]string{"IMAP4rev2"}, disabled...) {
				if slices.Contains(caps, name) {
					t.Errorf("CAPABILITY still offers %s:\n%s", name, capLine)
				}
			}

			c.appendMessage()

			c.wantBad("ESEARCH IN (personal) ALL")
			c.wantBad(`LIST (SUBSCRIBED) "" "*"`)
			c.wantBad(`LIST (SUBSCRIBED RECURSIVEMATCH) "" "*"`)
			c.wantBad(`LIST "" ("INBOX" "Arch")`)
			c.wantBad(`LIST "" "*" RETURN (SPECIAL-USE)`)
			c.wantBad(`LIST (SPECIAL-USE) "" "*"`)
			c.wantBad(`CREATE Arch (USE (\Archive))`)
			if resp := c.mustOK(`LIST "" "Arch"`); strings.Contains(resp, "* LIST ") {
				t.Errorf("a refused CREATE created the mailbox:\n%s", resp)
			}
			if resp := c.mustOK(`LIST "" "*"`); !strings.Contains(resp, "INBOX") {
				t.Errorf(`LIST "" "*": want INBOX, got:\n%s`, resp)
			}
			c.mustOK(`LSUB "" "*"`)
			c.mustOK("CREATE Plain")

			c.mustOK("SELECT INBOX")
			c.wantBad("ESEARCH ALL")
			c.wantBad("THREAD REFERENCES UTF-8 ALL")
			c.wantBad("UID THREAD REFS UTF-8 ALL")
			c.wantBad("THREAD ORDEREDSUBJECT UTF-8 ALL")
			c.mustOK(`STORE 1 +FLAGS.SILENT (\Deleted)`)
			c.wantBad("UID EXPUNGE 1")
			if resp := c.mustOK("SEARCH DELETED"); !strings.Contains(resp, "* SEARCH 1") {
				t.Errorf("a refused UID EXPUNGE expunged the message:\n%s", resp)
			}
			if resp := c.mustOK("EXPUNGE"); !strings.Contains(resp, "* 1 EXPUNGE") {
				t.Errorf("EXPUNGE: want * 1 EXPUNGE, got:\n%s", resp)
			}
		})
	}
}

// disabledCapsClient is a raw IMAP connection, logged in, to a server built
// with configure.
type disabledCapsClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	tagN int
}

// dialDisabledCaps starts a server with configure, connects and logs in; with
// identify it sends ID name "buggy", the client name the client_filters cases
// match.
func dialDisabledCaps(t *testing.T, configure func(*imapserver.IMAPServerOptions), identify bool) *disabledCapsClient {
	t.Helper()
	server, account, _ := common.SetupIMAPServerWithRealS3Options(t, configure)
	t.Cleanup(server.Close)

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &disabledCapsClient{t: t, conn: conn, r: bufio.NewReader(conn)}
	if _, err := c.r.ReadString('\n'); err != nil {
		t.Fatalf("read greeting failed: %v", err)
	}
	c.mustOK(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	if identify {
		c.mustOK(`ID ("name" "buggy")`)
	}
	return c
}

func (c *disabledCapsClient) do(cmd string) string {
	c.t.Helper()
	c.tagN++
	tag := fmt.Sprintf("x%d", c.tagN)
	if _, err := fmt.Fprintf(c.conn, "%s %s\r\n", tag, cmd); err != nil {
		c.t.Fatalf("write %q failed: %v", cmd, err)
	}
	return h3ReadTagged(c.t, c.r, tag)
}

func (c *disabledCapsClient) mustOK(cmd string) string {
	c.t.Helper()
	resp := c.do(cmd)
	if !strings.Contains(resp, " OK ") {
		c.t.Fatalf("%s not OK:\n%s", cmd, resp)
	}
	return resp
}

func (c *disabledCapsClient) wantBad(cmd string) {
	c.t.Helper()
	resp := c.do(cmd)
	if lines := strings.Split(strings.TrimSpace(resp), "\r\n"); !strings.Contains(lines[len(lines)-1], " BAD ") {
		c.t.Errorf("%s: want BAD, got:\n%s", cmd, resp)
	}
}

// appendMessage stores one message in INBOX.
func (c *disabledCapsClient) appendMessage() {
	c.t.Helper()
	msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: disabled caps\r\n\r\nbody\r\n"
	if _, err := fmt.Fprintf(c.conn, "a1 APPEND INBOX {%d+}\r\n%s\r\n", len(msg), msg); err != nil {
		c.t.Fatalf("write APPEND failed: %v", err)
	}
	if resp := h3ReadTagged(c.t, c.r, "a1"); !strings.Contains(resp, "a1 OK ") {
		c.t.Fatalf("APPEND not OK:\n%s", resp)
	}
}
