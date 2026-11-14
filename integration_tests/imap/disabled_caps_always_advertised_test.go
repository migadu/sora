//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_DisabledCapsCannotWithdrawAlwaysAdvertised: go-imap advertises
// SASL-IR and LITERAL- before login and UNSELECT and ENABLE after it on any
// IMAP4rev1 server, so disabled_caps cannot withdraw them. Naming them must
// leave the server on IMAP4rev2 (and LITERAL+) instead of downgrading it for
// nothing. This also pins the go-imap behaviour that alwaysAdvertisedCaps in
// server/imap mirrors: if one of these stops being listed, revisit that set.
func TestIMAP_DisabledCapsCannotWithdrawAlwaysAdvertised(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, _ := common.SetupIMAPServerWithRealS3Options(t, func(o *imapserver.IMAPServerOptions) {
		o.DisabledCaps = []string{"SASL-IR", "LITERAL-", "UNSELECT", "ENABLE"}
	})
	t.Cleanup(server.Close)

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	r := bufio.NewReader(conn)
	greeting, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting failed: %v", err)
	}
	_, rest, ok := strings.Cut(greeting, "[CAPABILITY ")
	preAuth, _, _ := strings.Cut(rest, "]")
	if !ok {
		t.Fatalf("greeting carries no CAPABILITY: %q", greeting)
	}
	for _, c := range []string{"IMAP4rev2", "SASL-IR", "LITERAL-"} {
		if !slices.Contains(strings.Fields(preAuth), c) {
			t.Errorf("greeting capabilities lack %s: %q", c, preAuth)
		}
	}

	tagN := 0
	do := func(cmd string) string {
		t.Helper()
		tagN++
		tag := fmt.Sprintf("a%d", tagN)
		if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
			t.Fatalf("write %q failed: %v", cmd, err)
		}
		return h3ReadTagged(t, r, tag)
	}
	if resp := do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)); !strings.Contains(resp, " OK ") {
		t.Fatalf("LOGIN not OK:\n%s", resp)
	}
	capLine, _, _ := strings.Cut(do("CAPABILITY"), "\r\n")
	for _, c := range []string{"IMAP4rev2", "UNSELECT", "ENABLE", "LITERAL+"} {
		if !slices.Contains(strings.Fields(capLine), c) {
			t.Errorf("CAPABILITY lacks %s:\n%s", c, capLine)
		}
	}
}
