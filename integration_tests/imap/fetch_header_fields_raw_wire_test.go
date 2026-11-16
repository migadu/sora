//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func readHeaderFieldsFetchResponse(t *testing.T, r *bufio.Reader, tag string) (string, [][]byte) {
	t.Helper()
	var wire strings.Builder
	var literals [][]byte
	for {
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		wire.WriteString(line)
		if strings.HasSuffix(line, "}\r\n") {
			start := strings.LastIndex(line, "{")
			n, err := strconv.Atoi(line[start+1 : len(line)-3])
			require.NoError(t, err)
			b := make([]byte, n)
			_, err = io.ReadFull(r, b)
			require.NoError(t, err)
			literals = append(literals, b)
			wire.Write(b)
		}
		if strings.HasPrefix(line, tag+" ") {
			require.True(t, strings.HasPrefix(line, tag+" OK"), wire.String())
			return wire.String(), literals
		}
	}
}

func TestIMAP_HeaderFieldsRawWire(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	conn, reader := dialAuthenticate(t, srv.Address)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	fmt.Fprintf(conn, "A1 LOGIN %q %q\r\n", account.Email, account.Password)
	readHeaderFieldsFetchResponse(t, reader, "A1")
	fmt.Fprint(conn, "A2 ENABLE IMAP4rev2\r\n")
	readHeaderFieldsFetchResponse(t, reader, "A2")
	const header = "From: a@example.com\r\nX(a: 1\r\nx(A: 2\r\nKey/s@1: 3\r\nSubject: s\r\n\r\n"
	const body = "payload KEEP\r\nX(a: body\r\n"
	msg := header + body
	fmt.Fprintf(conn, "A3 APPEND INBOX {%d+}\r\n%s\r\n", len(msg), msg)
	readHeaderFieldsFetchResponse(t, reader, "A3")
	fmt.Fprint(conn, "A4 SELECT INBOX\r\n")
	readHeaderFieldsFetchResponse(t, reader, "A4")
	for n, tc := range []struct{ name, section, want string }{
		{"NOT odd mixed case", `HEADER.FIELDS.NOT ("x(a")`, "From: a@example.com\r\nKey/s@1: 3\r\nSubject: s\r\n\r\n"},
		{"NOT two odd names", `HEADER.FIELDS.NOT ("X(A" "kEY/S@1")`, "From: a@example.com\r\nSubject: s\r\n\r\n"},
		{"NOT unicode lookalike", `HEADER.FIELDS.NOT ("Key/s@1")`, header},
		{"positive aliases", `HEADER.FIELDS ("x(a")`, "X(a: 1\r\nx(A: 2\r\n\r\n"},
		{"positive unicode lookalike", `HEADER.FIELDS ("Key/s@1")`, "\r\n"},
		{"NOT partial", `HEADER.FIELDS.NOT ("x(a")]<3.11>`, "m: a@exampl"},
		{"body text unchanged", `TEXT`, body},
		{"whole message unchanged", ``, msg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag := fmt.Sprintf("B%d", n)
			section := "BODY.PEEK[" + tc.section + "]"
			if strings.Contains(tc.section, "]<") {
				section = "BODY.PEEK[" + tc.section
			}
			fmt.Fprintf(conn, "%s FETCH 1 (UID FLAGS %s)\r\n", tag, section)
			wire, got := readHeaderFieldsFetchResponse(t, reader, tag)
			require.Len(t, got, 1)
			require.Equal(t, tc.want, string(got[0]), "wire=%q", wire)
			require.NotContains(t, wire, `\Seen`, "PEEK must not set Seen")
			t.Logf("%s => %q", section, wire)
		})
	}
	fmt.Fprint(conn, "C1 FETCH 1 (BODY[HEADER.FIELDS.NOT (\"x(a\")])\r\n")
	readHeaderFieldsFetchResponse(t, reader, "C1")
	fmt.Fprint(conn, "C2 FETCH 1 (FLAGS)\r\n")
	wire, _ := readHeaderFieldsFetchResponse(t, reader, "C2")
	require.Contains(t, wire, `\Seen`, "ordinary BODY fetch retains implicit Seen")
}
