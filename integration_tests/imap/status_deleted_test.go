//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_StatusDeleted: DELETED is a STATUS data item of IMAP4rev2, "The
// number of messages that have the \Deleted flag set" (RFC 9051 §6.3.11), and
// LIST-STATUS returns the same items (RFC 5819 §2). Sora never filled it in,
// and go-imap failed the command after part of the STATUS line was on the
// wire, so the tagged NO came glued to it (#1063):
//
//   - STATUS INBOX (MESSAGES 3x9 NO [SERVERBUG] Internal server error
//
// DELETED-STORAGE belongs to QUOTA=RES-STORAGE (RFC 9208 §4.1.4): the size of the
// \Deleted messages, which Sora gives as the sum of their RFC822.SIZE.
func TestIMAP_StatusDeleted(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c := dialDisabledCaps(t, nil, false)

	// Four messages; the first is \Deleted and expunged, which must not count,
	// then two of the remaining three are flagged \Deleted.
	for range 4 {
		c.appendMessage()
	}
	c.mustOK("CREATE Empty")
	c.mustOK("SELECT INBOX")
	c.mustOK(`STORE 1 +FLAGS.SILENT (\Deleted)`)
	c.mustOK("EXPUNGE")
	c.mustOK(`STORE 1:2 +FLAGS.SILENT (\Deleted \Seen)`)
	// The test messages are all the same size.
	var size int
	if _, err := fmt.Sscanf(c.mustOK("FETCH 1 (RFC822.SIZE)"), "* 1 FETCH (RFC822.SIZE %d)", &size); err != nil || size == 0 {
		t.Fatalf("FETCH 1 (RFC822.SIZE): %v (size %d)", err, size)
	}
	c.mustOK("UNSELECT")
	deletedStorage := fmt.Sprintf("DELETED-STORAGE %d)\r\n", 2*size)

	for cmd, want := range map[string][]string{
		"STATUS INBOX (MESSAGES DELETED)":                       {"* STATUS INBOX (MESSAGES 3 DELETED 2)\r\n"},
		"STATUS INBOX (DELETED UNSEEN)":                         {"* STATUS INBOX (UNSEEN 1 DELETED 2)\r\n"},
		"STATUS Empty (DELETED)":                                {"* STATUS \"Empty\" (DELETED 0)\r\n"},
		`LIST "" "INBOX" RETURN (STATUS (MESSAGES DELETED))`:    {"* STATUS INBOX (MESSAGES 3 DELETED 2)\r\n"},
		`LIST "" "*" RETURN (STATUS (DELETED))`:                 {"* STATUS INBOX (DELETED 2)\r\n", "* STATUS \"Empty\" (DELETED 0)\r\n"},
		`LIST "" "Empty" RETURN (STATUS (MESSAGES DELETED))`:    {"* STATUS \"Empty\" (MESSAGES 0 DELETED 0)\r\n"},
		`LIST "" "INBOX" RETURN (STATUS (UIDVALIDITY DELETED))`: {" DELETED 2)\r\n"},
		"STATUS INBOX (DELETED-STORAGE)":                        {"* STATUS INBOX (" + deletedStorage},
		"STATUS INBOX (MESSAGES DELETED-STORAGE)":               {"* STATUS INBOX (MESSAGES 3 " + deletedStorage},
		"STATUS Empty (DELETED-STORAGE)":                        {"* STATUS \"Empty\" (DELETED-STORAGE 0)\r\n"},
		`LIST "" "INBOX" RETURN (STATUS (DELETED-STORAGE))`:     {"* STATUS INBOX (" + deletedStorage},
		`LIST "" "*" RETURN (STATUS (DELETED DELETED-STORAGE))`: {"* STATUS INBOX (DELETED 2 " + deletedStorage, "* STATUS \"Empty\" (DELETED 0 DELETED-STORAGE 0)\r\n"},
	} {
		resp, tagged := statusDeletedDo(c, cmd)
		if !strings.Contains(tagged, " OK ") || !strings.HasPrefix(tagged, "x") {
			t.Errorf("%s: want a tagged OK on its own line, got:\n%s", cmd, resp)
			continue
		}
		for _, w := range want {
			if !strings.Contains(resp, w) {
				t.Errorf("%s: want %q, got:\n%s", cmd, w, resp)
			}
		}
	}

}

// TestIMAP_StatusDeletedStorageNeedsQuota: without QUOTA (here withdrawn by
// disabled_caps) DELETED-STORAGE is refused like any other unknown argument ("BAD -
// command unknown or arguments invalid", RFC 9051 §6.3.11), before any of the
// STATUS line is written (#1063).
func TestIMAP_StatusDeletedStorageNeedsQuota(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c := dialDisabledCaps(t, func(o *imapserver.IMAPServerOptions) {
		o.DisabledCaps = []string{"QUOTA"}
	}, false)
	c.appendMessage()

	for _, cmd := range []string{
		"STATUS INBOX (DELETED-STORAGE)",
		"STATUS INBOX (MESSAGES DELETED-STORAGE)",
		`LIST "" "INBOX" RETURN (STATUS (DELETED-STORAGE))`,
		`LIST "" "*" RETURN (STATUS (MESSAGES DELETED-STORAGE))`,
	} {
		statusDeletedWantOnlyBad(t, c, cmd)
	}
	// The connection is still in step after the refusals.
	c.mustOK("NOOP")
}

// TestIMAP_StatusDeletedNeedsIMAP4rev2: RFC 3501 has no DELETED status data
// item, so a session that is not offered IMAP4rev2 (here a client filter takes
// it away) refuses it like an unknown argument.
func TestIMAP_StatusDeletedNeedsIMAP4rev2(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c := dialDisabledCaps(t, func(o *imapserver.IMAPServerOptions) {
		o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: []string{"IMAP4rev2"}}}
	}, true)

	capLine, _, _ := strings.Cut(c.do("CAPABILITY"), "\r\n")
	if strings.Contains(capLine, "IMAP4rev2") || !strings.Contains(capLine, "LIST-STATUS") {
		t.Fatalf("want LIST-STATUS without IMAP4rev2, got:\n%s", capLine)
	}

	for _, cmd := range []string{
		"STATUS INBOX (DELETED)",
		"STATUS INBOX (MESSAGES DELETED)",
		`LIST "" "INBOX" RETURN (STATUS (MESSAGES DELETED))`,
	} {
		statusDeletedWantOnlyBad(t, c, cmd)
	}
	if resp := c.mustOK("STATUS INBOX (MESSAGES)"); !strings.Contains(resp, "* STATUS INBOX (MESSAGES 0)\r\n") {
		t.Errorf("STATUS INBOX (MESSAGES): want MESSAGES 0, got:\n%s", resp)
	}
}

// statusDeletedWantOnlyBad sends cmd and wants nothing back but a tagged BAD.
func statusDeletedWantOnlyBad(t *testing.T, c *disabledCapsClient, cmd string) {
	t.Helper()
	resp, tagged := statusDeletedDo(c, cmd)
	if resp != tagged || !strings.HasPrefix(tagged, "x") || !strings.Contains(tagged, " BAD ") {
		t.Errorf("%s: want only a tagged BAD, got:\n%s", cmd, resp)
	}
}

// statusDeletedDo sends cmd and reads up to its tagged response, which it also
// returns. Unlike disabledCapsClient.do it also stops at a tagged response
// glued to the end of an unterminated untagged line, so the test fails at once
// instead of waiting for the connection deadline.
func statusDeletedDo(c *disabledCapsClient, cmd string) (resp, tagged string) {
	c.t.Helper()
	c.tagN++
	tag := fmt.Sprintf("x%d", c.tagN)
	if _, err := fmt.Fprintf(c.conn, "%s %s\r\n", tag, cmd); err != nil {
		c.t.Fatalf("write %q failed: %v", cmd, err)
	}
	var sb strings.Builder
	for {
		line, err := c.r.ReadString('\n')
		sb.WriteString(line)
		if err != nil {
			c.t.Fatalf("read until tag %q failed: %v (partial:\n%s)", tag, err, sb.String())
		}
		for _, status := range []string{" OK ", " NO ", " BAD "} {
			if strings.HasPrefix(line, tag+" ") || strings.Contains(line, tag+status) {
				return sb.String(), line
			}
		}
	}
}
