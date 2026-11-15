//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

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
			// Every attribute sora supports belongs to a default mailbox, so
			// CREATE ... USE would fail with NO [USEATTR] anyway; free \Archive
			// so that a CREATE that is not refused creates Arch.
			c.clearSpecialUse(`\Archive`)
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
	t       *testing.T
	server  *common.TestServer
	account common.TestAccount
	conn    net.Conn
	r       *bufio.Reader
	tagN    int
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
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	c := &disabledCapsClient{t: t, server: server, account: account, conn: conn, r: bufio.NewReader(conn)}
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

// clearSpecialUse takes special-use attribute attr off the account's mailbox
// that has it, in the database.
func (c *disabledCapsClient) clearSpecialUse(attr string) {
	c.t.Helper()
	ctx := context.Background()
	accountID, err := c.server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, c.account.Email)
	if err != nil {
		c.t.Fatalf("account ID: %v", err)
	}
	tag, err := c.server.ResilientDB.GetOperationalDatabase().WritePool.Exec(ctx,
		"UPDATE mailboxes SET special_use = NULL WHERE account_id = $1 AND special_use = $2", accountID, attr)
	if err != nil {
		c.t.Fatalf("clear %s: %v", attr, err)
	}
	if tag.RowsAffected() != 1 {
		c.t.Fatalf("clear %s: %d mailboxes had it, want 1", attr, tag.RowsAffected())
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

// The LIST options have independent capability strings (RFC 5258 section 3).
// RFC 6154 section 5.2 explicitly shows SPECIAL-USE without LIST-EXTENDED.
func TestIMAP_DisabledListExtendedKeepsIndependentOptions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, identify := range []bool{false, true} {
		t.Run(fmt.Sprintf("client_filter=%v", identify), func(t *testing.T) {
			c := dialDisabledCaps(t, func(o *imapserver.IMAPServerOptions) {
				if identify {
					o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: []string{"LIST-EXTENDED"}}}
				} else {
					o.DisabledCaps = []string{"LIST-EXTENDED"}
				}
			}, identify)
			capLine, _, _ := strings.Cut(c.do("CAPABILITY"), "\r\n")
			caps := strings.Fields(capLine)
			if slices.Contains(caps, "LIST-EXTENDED") || !slices.Contains(caps, "SPECIAL-USE") || !slices.Contains(caps, "LIST-STATUS") {
				t.Fatalf("independent LIST-option capabilities changed: %s", capLine)
			}
			for _, cmd := range []string{
				`LIST "" "*" RETURN (SPECIAL-USE)`,
				`LIST (SPECIAL-USE) "" "*"`,
				`LIST "" "INBOX" RETURN (STATUS (MESSAGES))`,
				`LIST (SPECIAL-USE) "" "*" RETURN (STATUS (MESSAGES) SPECIAL-USE)`,
			} {
				c.mustOK(cmd)
			}
			// Specialized options do not authorize generic extended syntax.
			c.wantBad(`LIST (SUBSCRIBED SPECIAL-USE) "" "*"`)
			c.wantBad(`LIST "" ("INBOX") RETURN (SPECIAL-USE)`)
			c.mustOK("NOOP")
		})
	}
}

// TestIMAP_DisabledCapsRefusesImpliedExtensions verifies that disabling
// SPECIAL-USE or ESEARCH (via disabled_caps or client_filters) also withdraws
// and refuses the extensions that RFC-imply them (#1011): CREATE-SPECIAL-USE ->
// SPECIAL-USE (RFC 6154 §3), and SEARCHRES (RFC 5182 §2.1), ESORT (RFC 5267
// §3.1) and MULTISEARCH (RFC 7377) -> ESEARCH.
func TestIMAP_DisabledCapsRefusesImpliedExtensions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	for _, mode := range []struct {
		name     string
		identify bool
	}{
		{"disabled_caps", false},
		{"client_filters", true},
	} {
		t.Run(mode.name+"/SPECIAL-USE", func(t *testing.T) {
			c := dialDisabledCaps(t, func(o *imapserver.IMAPServerOptions) {
				if mode.identify {
					o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: []string{"SPECIAL-USE"}}}
				} else {
					o.DisabledCaps = []string{"SPECIAL-USE"}
				}
			}, mode.identify)

			capLine, _, _ := strings.Cut(c.do("CAPABILITY"), "\r\n")
			caps := strings.Fields(capLine)
			for _, name := range []string{"SPECIAL-USE", "CREATE-SPECIAL-USE"} {
				if slices.Contains(caps, name) {
					t.Errorf("CAPABILITY still offers %s:\n%s", name, capLine)
				}
			}
			if !slices.Contains(caps, "IMAP4rev2") {
				t.Errorf("CAPABILITY lost IMAP4rev2 when disabling SPECIAL-USE:\n%s", capLine)
			}

			c.clearSpecialUse(`\Archive`)
			c.wantBad(`CREATE Arch (USE (\Archive))`)
			if resp := c.mustOK(`LIST "" "Arch"`); strings.Contains(resp, "* LIST ") {
				t.Errorf("a refused CREATE created the mailbox:\n%s", resp)
			}
			c.wantBad(`LIST (SPECIAL-USE) "" "*"`)
			c.wantBad(`LIST "" "*" RETURN (SPECIAL-USE)`)
			c.mustOK("CREATE Plain")
		})

		t.Run(mode.name+"/ESEARCH", func(t *testing.T) {
			c := dialDisabledCaps(t, func(o *imapserver.IMAPServerOptions) {
				if mode.identify {
					o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: []string{"ESEARCH"}}}
				} else {
					o.DisabledCaps = []string{"ESEARCH"}
				}
			}, mode.identify)

			capLine, _, _ := strings.Cut(c.do("CAPABILITY"), "\r\n")
			caps := strings.Fields(capLine)
			for _, name := range []string{"IMAP4rev2", "ESEARCH", "SEARCHRES", "ESORT", "MULTISEARCH"} {
				if slices.Contains(caps, name) {
					t.Errorf("CAPABILITY still offers %s:\n%s", name, capLine)
				}
			}
			for _, name := range []string{"IMAP4rev1", "SORT", "SORT=DISPLAY"} {
				if !slices.Contains(caps, name) {
					t.Errorf("CAPABILITY lost %s:\n%s", name, capLine)
				}
			}

			c.appendMessage()

			c.wantBad("ESEARCH IN (personal) ALL")

			c.mustOK("SELECT INBOX")
			c.wantBad("ESEARCH ALL")
			c.wantBad("ESEARCH IN (selected) RETURN (SAVE) ALL")
			c.wantBad("SEARCH RETURN (SAVE) ALL")
			c.wantBad("UID SEARCH RETURN (SAVE) ALL")
			c.wantBad("SEARCH RETURN (COUNT) ALL")
			c.wantBad("SORT RETURN (ALL) (DATE) UTF-8 ALL")
			c.wantBad("SORT RETURN (COUNT) (DATE) UTF-8 ALL")
			c.wantBad("UID SORT RETURN (MIN MAX) (DATE) UTF-8 ALL")

			if resp := c.mustOK("SEARCH ALL"); !strings.Contains(resp, "* SEARCH 1") {
				t.Errorf("plain SEARCH ALL: want * SEARCH 1, got:\n%s", resp)
			}
			if resp := c.mustOK("SORT (DATE) UTF-8 ALL"); !strings.Contains(resp, "* SORT 1") {
				t.Errorf("plain SORT: want * SORT 1, got:\n%s", resp)
			}
			if resp := c.mustOK("SORT (DISPLAYFROM) UTF-8 ALL"); !strings.Contains(resp, "* SORT 1") {
				t.Errorf("SORT (DISPLAYFROM): want * SORT 1, got:\n%s", resp)
			}
		})
	}
}
