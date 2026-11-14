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
