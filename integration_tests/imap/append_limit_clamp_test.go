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

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapServer "github.com/migadu/sora/server/imap"
)

// An append_limit of 4 GiB or more must reach the client as the largest
// message sora can store in CAPABILITY, STATUS and LIST-STATUS alike, and a
// small APPEND must still be accepted. That is 2147483647: messages.size is an
// INTEGER column, and RFC 7889 section 5 makes APPENDLIMIT "the fixed maximum
// message size in octets that the server will accept" (#492). It is also inside
// the RFC 3501 "number" (an unsigned 32-bit integer) APPENDLIMIT is written
// as: converting the int64 with uint32() wrapped "4gb" to APPENDLIMIT=0 (every
// APPEND refused with NO [TOOBIG]) and "5gb" to 1 GiB (#333). An unset limit
// (0) must report the 25 MB default it enforces in STATUS too, not NIL ("no
// APPENDLIMIT for that mailbox", RFC 7889 section 3).
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
		{"4gb", 4 * gib, math.MaxInt32},
		{"5gb", 5 * gib, math.MaxInt32},
		{"unset", 0, imapServer.DefaultAppendLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, account, _ := common.SetupIMAPServerWithRealS3Options(t, func(o *imapServer.IMAPServerOptions) {
				o.AppendLimit = tt.configured
				o.SessionMemoryLimit = 0 // unlimited: only append_limit counts here
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

// APPEND reads the whole literal into memory charged to the session memory
// budget (session_memory_limit), so it never accepts a message larger than
// that budget. RFC 7889 section 5: "The number indicates the fixed maximum
// message size in octets that the server will accept." APPENDLIMIT must
// therefore be the smaller of append_limit and the budget, in CAPABILITY,
// STATUS and LIST-STATUS. A message of that size must be accepted, and one
// octet more refused with NO [TOOBIG] (RFC 7889 section 4) before the client
// is asked to send it, not read and then answered NO [UNAVAILABLE] "please try
// again later", which can never succeed (#492). session_memory_limit is
// reloadable, so a session started after a reload advertises its new budget.
func TestIMAP_AppendLimitCappedBySessionMemory(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const budget = 1 << 20
	server, account, _ := common.SetupIMAPServerWithRealS3Options(t, func(o *imapServer.IMAPServerOptions) {
		o.AppendLimit = 25 << 20
		o.SessionMemoryLimit = budget
	})
	defer server.Close()

	statusLimit := regexp.MustCompile(`^\* STATUS "?INBOX"? \(APPENDLIMIT ([^ )]+)\)`)
	capLimit := regexp.MustCompile(`^\* CAPABILITY .*\bAPPENDLIMIT=(\S+)`)
	limitIn := func(lines []string, pattern *regexp.Regexp) string {
		for _, line := range lines {
			if m := pattern.FindStringSubmatch(line); m != nil {
				return m[1]
			}
		}
		return "<missing>"
	}
	login := func() *rawIMAP {
		c := dialRawIMAP(t, server.Address)
		c.conn.SetDeadline(time.Now().Add(60 * time.Second))
		c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
		return c
	}
	advertised := func(c *rawIMAP) string {
		capLines, _ := c.do("CAPABILITY")
		return limitIn(capLines, capLimit)
	}

	c := login()
	want := strconv.Itoa(budget)
	if got := advertised(c); got != want {
		t.Errorf("CAPABILITY APPENDLIMIT=%s, want %s (session_memory_limit)", got, want)
	}
	statusLines, _ := c.do("STATUS INBOX (APPENDLIMIT)")
	if got := limitIn(statusLines, statusLimit); got != want {
		t.Errorf("STATUS INBOX (APPENDLIMIT %s), want %s", got, want)
	}
	listLines, _ := c.do(`LIST "" INBOX RETURN (STATUS (APPENDLIMIT))`)
	if got := limitIn(listLines, statusLimit); got != want {
		t.Errorf("LIST-STATUS INBOX (APPENDLIMIT %s), want %s", got, want)
	}

	readLine := func() string {
		line, err := c.r.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}

	// A message of exactly the advertised size is accepted.
	msg := messageOfSize(budget)
	tag := c.nextTag()
	fmt.Fprintf(c.conn, "%s APPEND INBOX {%d}\r\n", tag, len(msg))
	if line := readLine(); !strings.HasPrefix(line, "+") {
		t.Fatalf("APPEND of a %d-byte message: got %q, want a continuation request", len(msg), line)
	}
	fmt.Fprintf(c.conn, "%s\r\n", msg)
	if _, tagged := c.read(tag, "APPEND"); !strings.HasPrefix(tagged, tag+" OK") {
		t.Errorf("APPEND of a %d-byte message (the advertised APPENDLIMIT): got %q, want OK", len(msg), tagged)
	}

	// One octet more is refused outright, before the literal is sent.
	tag = c.nextTag()
	fmt.Fprintf(c.conn, "%s APPEND INBOX {%d}\r\n", tag, budget+1)
	if line := readLine(); !strings.HasPrefix(line, tag+" NO [TOOBIG]") {
		t.Fatalf("APPEND of a %d-byte message: got %q, want %s NO [TOOBIG] before a continuation request", budget+1, line, tag)
	}

	// A reload of session_memory_limit reaches the sessions started after it;
	// this one keeps the budget it started with.
	imapSrv, ok := server.Server.(*imapServer.IMAPServer)
	if !ok {
		t.Fatalf("server.Server is %T, want *imap.IMAPServer", server.Server)
	}
	if err := imapSrv.ReloadConfig(config.ServerConfig{
		Limits: &config.ServerLimitsConfig{SessionMemoryLimit: "2mb"},
	}); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	if got, reloaded := advertised(login()), strconv.Itoa(2<<20); got != reloaded {
		t.Errorf("after reloading session_memory_limit to 2mb, a new session advertises APPENDLIMIT=%s, want %s", got, reloaded)
	}
	if got := advertised(c); got != want {
		t.Errorf("after the reload, the session started before it advertises APPENDLIMIT=%s, want %s", got, want)
	}
}

// messageOfSize returns an RFC 5322 message of exactly n octets.
func messageOfSize(n int) string {
	var b strings.Builder
	b.WriteString("Subject: append limit\r\n\r\n")
	line := strings.Repeat("x", 76) + "\r\n"
	for b.Len() < n {
		b.WriteString(line)
	}
	return b.String()[:n]
}
