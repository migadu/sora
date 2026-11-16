//go:build integration

package imap_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// A fixed-zero date can decode into time.UTC when the application uses that
// location as time.Local. Both the SQL envelope and the gob-encoded attached
// envelope must retain their own explicit zone status, including after COPY/MOVE.
func TestIMAP_ExplicitEnvelopeZonesSurvivePersistenceLocalUTC(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	const childEnv = "SORA_TEST_EXPLICIT_ENVELOPE_ZONE_LOCAL_UTC"
	if os.Getenv(childEnv) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestIMAP_ExplicitEnvelopeZonesSurvivePersistenceLocalUTC$", "-test.count=1", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "isolated UTC persistence checks: %s", output)
		require.NotContains(t, string(output), "--- SKIP:", "the isolated persistence checks must run")
		return
	}
	time.Local = time.UTC
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	cases := []struct {
		outer, inner         string
		wantOuter, wantInner string
	}{
		{"Wed, 17 Jul 1996 02:23:25 +0000", "Wed, 17 Jul 1996 02:23:25 GMT+1", `"Wed, 17 Jul 1996 02:23:25 +0000"`, `"Wed, 17 Jul 1996 02:23:25 -0000"`},
		{"Wed, 17 Jul 1996 02:23:25 GMT+1", "Wed, 17 Jul 1996 02:23:25 +0000", `"Wed, 17 Jul 1996 02:23:25 -0000"`, `"Wed, 17 Jul 1996 02:23:25 +0000"`},
		{"Wed, 17 Jul 1996 02:23:25 UT", "Wed, 17 Jul 1996 02:23:25 -0000", `"Wed, 17 Jul 1996 02:23:25 +0000"`, `"Wed, 17 Jul 1996 02:23:25 -0000"`},
		{"Wed, 17 Jul 1996 02:23:25 Z", "Wed, 17 Jul 1996 02:23:25 GMT", `"Wed, 17 Jul 1996 02:23:25 -0000"`, `"Wed, 17 Jul 1996 02:23:25 +0000"`},
		{"Wed, 17 Jul 1996 02:23:25 +0545", "Wed, 17 Jul 1996 02:23:25 -0700", `"Wed, 17 Jul 1996 02:23:25 +0545"`, `"Wed, 17 Jul 1996 02:23:25 -0700"`},
		{"", "not a date", "NIL", "NIL"},
	}
	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)
	for i, tc := range cases {
		dateHeader := ""
		if tc.outer != "" {
			dateHeader = "Date: " + tc.outer + "\r\n"
		}
		// Exercise both attached message types through the same storage path.
		subtype := "rfc822"
		if i%2 != 0 {
			subtype = "global"
		}
		message := "From: alice@example.com\r\n" + dateHeader +
			fmt.Sprintf("Subject: outer%d\r\nContent-Type: message/%s\r\n\r\n", i, subtype) +
			fmt.Sprintf("Date: %s\r\nSubject: inner%d\r\nContent-Type: text/plain\r\n\r\nbody\r\n", tc.inner, i)
		rc.append(fmt.Sprintf("a%d", i), "INBOX", message)
	}
	for _, mailbox := range []string{"Copied", "Moved"} {
		_, tagged := rc.cmd("c", "CREATE "+mailbox)
		require.Contains(t, tagged, "OK")
	}
	_, tagged := rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = rc.cmd("cp", "COPY 1:* Copied")
	require.Contains(t, tagged, "OK")
	_, tagged = rc.cmd("mv", "MOVE 1:* Moved")
	require.Contains(t, tagged, "OK")
	require.NoError(t, rc.conn.Close())

	for _, mailbox := range []string{"Copied", "Moved"} {
		t.Run(mailbox, func(t *testing.T) {
			fresh := dialRaw(t, server.Address)
			defer fresh.conn.Close()
			fresh.login(account)
			_, tagged := fresh.cmd("s", "SELECT "+mailbox)
			require.Contains(t, tagged, "OK")
			for attempt := 0; attempt < 2; attempt++ {
				untagged, tagged := fresh.cmd("f", "FETCH 1:* (ENVELOPE BODYSTRUCTURE)")
				require.Contains(t, tagged, "OK")
				var responses []string
				for _, line := range untagged {
					if strings.Contains(line, " FETCH (") {
						responses = append(responses, line)
					}
				}
				require.Len(t, responses, len(cases))
				for i, tc := range cases {
					require.Contains(t, responses[i], fmt.Sprintf("ENVELOPE (%s \"outer%d\" ", tc.wantOuter, i))
					require.Contains(t, responses[i], fmt.Sprintf("(%s \"inner%d\" ", tc.wantInner, i))
				}
			}
		})
	}
}
