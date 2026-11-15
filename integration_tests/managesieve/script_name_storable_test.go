//go:build integration

package managesieve

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// A script name PostgreSQL cannot hold (a NUL, invalid UTF-8) names no script, so
// GETSCRIPT, DELETESCRIPT, SETACTIVE and RENAMESCRIPT answer NO (NONEXISTENT), as for
// any unknown script (RFC 5804 sections 2.8 to 2.11). The name was sent to the
// database, which refused it with SQLSTATE 22021, and the client was told
// NO (TRYLATER): "A command failed due to a temporary server failure" (section 1.3).
func TestScriptCommands_UnstorableName(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	for _, name := range []string{"a\x00b", "\xff", "caf\xc3"} {
		quoted := `"` + name + `"` // the raw bytes, not Go escapes
		for _, cmd := range []string{
			"GETSCRIPT " + quoted,
			"DELETESCRIPT " + quoted,
			"SETACTIVE " + quoted,
			"RENAMESCRIPT " + quoted + ` "renamed"`,
		} {
			fmt.Fprintf(w, "%s\r\n", cmd)
			w.Flush()
			if resp := msReadResp(t, conn, r); !strings.HasPrefix(resp, "NO (NONEXISTENT)") {
				t.Errorf("%q: got %q, want NO (NONEXISTENT)", cmd, resp)
			}
		}
	}
}

// Script content with NUL or invalid UTF-8 violates RFC 5228 sections 1.1 and 8.1 and
// cannot be stored in PostgreSQL text columns. Both CHECKSCRIPT and PUTSCRIPT (creating or
// updating) must refuse it with a permanent validation NO rather than CHECKSCRIPT
// answering OK and PUTSCRIPT answering NO (TRYLATER).
func TestScriptCommands_UnstorableContent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	valid := "keep;\r\n"
	fmt.Fprintf(w, "PUTSCRIPT \"existing\" {%d+}\r\n%s\r\n", len(valid), valid)
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("seed PUTSCRIPT: got %q, want OK", resp)
	}

	for _, tc := range []struct {
		name   string
		script string
	}{
		{"NUL in hash comment", "# \x00\r\nkeep;\r\n"},
		{"NUL in bracket comment", "/* \x00 */\r\nkeep;\r\n"},
		{"NUL in quoted string", "require \"fileinto\";\r\nfileinto \"a\x00b\";\r\n"},
		{"invalid UTF-8 in hash comment", "# \xff\r\nkeep;\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cmd := range []string{
				fmt.Sprintf("CHECKSCRIPT {%d+}\r\n%s", len(tc.script), tc.script),
				fmt.Sprintf("PUTSCRIPT \"fresh\" {%d+}\r\n%s", len(tc.script), tc.script),
				fmt.Sprintf("PUTSCRIPT \"existing\" {%d+}\r\n%s", len(tc.script), tc.script),
			} {
				verb, _, _ := strings.Cut(cmd, " ")
				fmt.Fprintf(w, "%s\r\n", cmd)
				w.Flush()
				resp := msReadResp(t, conn, r)
				if !strings.HasPrefix(resp, "NO ") || strings.HasPrefix(resp, "NO (TRYLATER)") {
					t.Errorf("%s (%s): got %q, want permanent validation NO (not OK or TRYLATER)", verb, tc.name, resp)
				}
			}
		})
	}
}
