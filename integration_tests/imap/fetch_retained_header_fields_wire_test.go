//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_RetainedHeaderFieldsWire(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	conn, reader := dialAuthenticate(t, srv.Address)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	fmt.Fprintf(conn, "A1 LOGIN %q %q\r\n", account.Email, account.Password)
	readHeaderFieldsFetchResponse(t, reader, "A1")
	const header = "From: a@example.com\r\nA: 1\r\nB: 2\r\nX\"Q: quoted\r\nX\\Q: slash\r\nSubject: s\r\n\r\n"
	const body = "payload KEEP\r\n"
	msg := header + body
	fmt.Fprintf(conn, "A2 APPEND INBOX {%d+}\r\n%s\r\n", len(msg), msg)
	readHeaderFieldsFetchResponse(t, reader, "A2")
	fmt.Fprint(conn, "A3 SELECT INBOX\r\n")
	readHeaderFieldsFetchResponse(t, reader, "A3")
	for n, tc := range []struct{ name, first, second, want string }{
		{"one spaced name versus two names", `HEADER.FIELDS ("A B")`, `HEADER.FIELDS (A B)`, "A: 1\r\nB: 2\r\n\r\n"},
		{"list delimiters across positive and negative lists", `HEADER.FIELDS ("]|[q")`, `HEADER.FIELDS.NOT ("q]|[")`, header},
		{"quoted character versus backslash", `HEADER.FIELDS ("X\"Q")`, `HEADER.FIELDS ("X\\Q")`, "X\\Q: slash\r\n\r\n"},
		{"backslash character versus quote", `HEADER.FIELDS ("X\\Q")`, `HEADER.FIELDS ("X\"Q")`, "X\"Q: quoted\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, section := range []string{tc.first, tc.second} {
				tag := fmt.Sprintf("B%d%d", n, i)
				fmt.Fprintf(conn, "%s FETCH 1 (UID FLAGS BODY.PEEK[%s]<0.4096>)\r\n", tag, section)
				wire, literals := readHeaderFieldsFetchResponse(t, reader, tag)
				require.Len(t, literals, 1, wire)
				require.Contains(t, wire, "BODY["+strings.ReplaceAll(section, "(A B)", `("A" "B")`)+"]<0>", "response must identify its requested section")
				require.NotContains(t, wire, `\Seen`, "PEEK must not set Seen")
				if i == 1 {
					require.Equal(t, tc.want, string(literals[0]), wire)
				}
			}
		})
	}
	fmt.Fprint(conn, "C1 FETCH 1 (BODY.PEEK[TEXT])\r\n")
	wire, literals := readHeaderFieldsFetchResponse(t, reader, "C1")
	require.Len(t, literals, 1, wire)
	require.Equal(t, body, string(literals[0]))
}
