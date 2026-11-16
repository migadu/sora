//go:build integration

package imap_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ListReturnMetadataOnlyWhenAdvertised: RETURN (METADATA) is the
// LIST-METADATA return option (RFC 9590 §1), and RFC 5258 §3 says "a client
// MUST NOT send an option for which the server has not advertised support. A
// server MUST respond to options it does not recognize with a BAD response."
// With the default capabilities LIST-METADATA was not advertised, yet the option
// was served with a METADATA response per listed mailbox (#889).
func TestIMAP_ListReturnMetadataOnlyWhenAdvertised(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c := dialDisabledCaps(t, nil, false)

	capLine, _, _ := strings.Cut(c.do("CAPABILITY"), "\r\n")
	caps := strings.Fields(capLine)
	if !slices.Contains(caps, "METADATA") {
		t.Fatalf("CAPABILITY does not offer METADATA:\n%s", capLine)
	}
	advertised := slices.Contains(caps, "LIST-METADATA")

	c.mustOK(`SETMETADATA INBOX (/private/comment "hello")`)

	cmd := `LIST "" "INBOX" RETURN (METADATA (/private/comment))`
	resp := c.do(cmd)
	served := strings.Contains(resp, "* METADATA ")
	if served != advertised {
		t.Errorf("LIST-METADATA advertised = %v, but %s served METADATA = %v:\n%s", advertised, cmd, served, resp)
	}
	if lines := strings.Split(strings.TrimSpace(resp), "\r\n"); !advertised && !strings.Contains(lines[len(lines)-1], " BAD ") {
		t.Errorf("%s without LIST-METADATA: want BAD, got:\n%s", cmd, resp)
	}

	// METADATA itself and a LIST without the option are unaffected.
	if resp := c.mustOK(`GETMETADATA INBOX /private/comment`); !strings.Contains(resp, `"hello"`) {
		t.Errorf("GETMETADATA INBOX: want the value set above, got:\n%s", resp)
	}
	if resp := c.mustOK(`LIST "" "INBOX"`); !strings.Contains(resp, "* LIST ") {
		t.Errorf(`LIST "" "INBOX": want INBOX, got:\n%s`, resp)
	}
}
