//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	imapServer "github.com/migadu/sora/server/imap"
)

// An append_limit of 4 GiB or more must reach the client as the largest number
// IMAP can express (RFC 7889 section 5 uses the RFC 3501 "number", an unsigned
// 32-bit integer) in CAPABILITY, STATUS and LIST-STATUS alike, and a small
// APPEND must still be accepted. Converting the int64 with uint32() wrapped
// "4gb" to APPENDLIMIT=0 (every APPEND refused with NO [TOOBIG]) and "5gb" to
// 1 GiB (#333). An unset limit (0) must report the 25 MB default it enforces
// in STATUS too, not NIL ("no APPENDLIMIT for that mailbox", RFC 7889
// section 3).
//
// The wire is read raw: go-imap's client decodes STATUS APPENDLIMIT NIL as
// 4294967295 and its CapSet.AppendLimit ignores APPENDLIMIT=0, so it cannot
// tell the clamped value from NIL or a wrapped 0.
func TestIMAP_AppendLimitAbove32BitsIsClamped(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const gib = int64(1) << 30
	tests := []struct {
		name       string
		configured int64
		want       uint32
	}{
		{"4gb", 4 * gib, math.MaxUint32},
		{"5gb", 5 * gib, math.MaxUint32},
		{"unset", 0, imapServer.DefaultAppendLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, account, _ := common.SetupIMAPServerWithRealS3Options(t, func(o *imapServer.IMAPServerOptions) {
				o.AppendLimit = tt.configured
			})
			defer server.Close()

			conn, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Fatalf("Failed to connect: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			r := bufio.NewReader(conn)
			readLine := func() string {
				line, err := r.ReadString('\n')
				if err != nil {
					t.Fatalf("Failed to read line: %v", err)
				}
				return strings.TrimRight(line, "\r\n")
			}
			// run sends cmd and returns the untagged lines and the tagged line.
			run := func(tag, cmd string) ([]string, string) {
				fmt.Fprintf(conn, "%s %s\r\n", tag, cmd)
				var untagged []string
				for {
					line := readLine()
					if strings.HasPrefix(line, tag+" ") {
						return untagged, line
					}
					untagged = append(untagged, line)
				}
			}
			expectOK := func(tag, cmd string) []string {
				untagged, tagged := run(tag, cmd)
				if !strings.HasPrefix(tagged, tag+" OK") {
					t.Fatalf("%s: got %q", cmd, tagged)
				}
				return untagged
			}
			// limitIn returns the APPENDLIMIT value pattern captures in lines.
			limitIn := func(lines []string, pattern *regexp.Regexp) string {
				for _, line := range lines {
					if m := pattern.FindStringSubmatch(line); m != nil {
						return m[1]
					}
				}
				return "<missing>"
			}
			want := strconv.FormatUint(uint64(tt.want), 10)

			readLine() // greeting
			expectOK("a", fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))

			capLines := expectOK("b", "CAPABILITY")
			if got := limitIn(capLines, regexp.MustCompile(`^\* CAPABILITY .*\bAPPENDLIMIT=(\S+)`)); got != want {
				t.Errorf("CAPABILITY APPENDLIMIT=%s, want %s", got, want)
			}

			statusLines := expectOK("c", "STATUS INBOX (APPENDLIMIT)")
			if got := limitIn(statusLines, regexp.MustCompile(`^\* STATUS "?INBOX"? \(APPENDLIMIT ([^ )]+)\)`)); got != want {
				t.Errorf("STATUS INBOX (APPENDLIMIT %s), want %s", got, want)
			}

			listLines := expectOK("d", `LIST "" INBOX RETURN (STATUS (APPENDLIMIT))`)
			if got := limitIn(listLines, regexp.MustCompile(`^\* STATUS "?INBOX"? \(APPENDLIMIT ([^ )]+)\)`)); got != want {
				t.Errorf("LIST-STATUS INBOX (APPENDLIMIT %s), want %s", got, want)
			}

			msg := "Subject: append limit\r\n\r\nbody\r\n"
			fmt.Fprintf(conn, "e APPEND INBOX {%d}\r\n", len(msg))
			if line := readLine(); !strings.HasPrefix(line, "+") {
				t.Fatalf("APPEND of a %d-byte message: got %q, want a continuation request", len(msg), line)
			}
			fmt.Fprintf(conn, "%s\r\n", msg)
			for {
				line := readLine()
				if strings.HasPrefix(line, "e ") {
					if !strings.HasPrefix(line, "e OK") {
						t.Errorf("APPEND of a %d-byte message: got %q", len(msg), line)
					}
					break
				}
			}
		})
	}
}
