//go:build integration

package imapproxy_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyGreetingCapabilities pins the pre-auth capability list the
// proxy advertises and checks that every token is a promise the pre-auth
// loop actually keeps. It exists because the greeting once carried a bare
// "LOGIN" token — not a capability at all, and read as a SASL mechanism it
// advertised something AUTHENTICATE refused — and omitted SASL-IR/LITERAL-
// even though both were accepted. The greeting and the CAPABILITY response
// are built from one constant; this test guards the constant.
func TestIMAPProxyGreetingCapabilities(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	time.Sleep(300 * time.Millisecond)

	dial := func(t *testing.T) (net.Conn, *bufio.Reader, string) {
		t.Helper()
		conn, err := net.Dial("tcp", proxyAddress)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader := bufio.NewReader(conn)
		greeting, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("greeting: %v", err)
		}
		return conn, reader, strings.TrimSpace(greeting)
	}

	// capsFromBracket extracts the token list from "* OK [CAPABILITY ...] text".
	capsFromBracket := func(t *testing.T, line string) []string {
		t.Helper()
		start := strings.Index(line, "[CAPABILITY ")
		end := strings.Index(line, "]")
		if start < 0 || end < start {
			t.Fatalf("no CAPABILITY response code in greeting: %q", line)
		}
		return strings.Fields(line[start+len("[CAPABILITY ") : end])
	}

	t.Run("exact_token_list", func(t *testing.T) {
		conn, _, greeting := dial(t)
		defer conn.Close()

		want := strings.Fields(imapproxy.PreAuthCapabilities)
		got := capsFromBracket(t, greeting)
		// The proxy may append configured extra caps (additionalCapsSuffix);
		// the pinned list must be an exact prefix.
		if len(got) < len(want) || strings.Join(got[:len(want)], " ") != strings.Join(want, " ") {
			t.Fatalf("greeting caps = %v, want prefix %v", got, want)
		}

		// Pin the exact expected surface so any change is a conscious edit here.
		const pinned = "IMAP4rev2 IMAP4rev1 SASL-IR LITERAL- AUTH=PLAIN"
		if imapproxy.PreAuthCapabilities != pinned {
			t.Fatalf("PreAuthCapabilities = %q, want %q (update this test deliberately)", imapproxy.PreAuthCapabilities, pinned)
		}

		for _, c := range got {
			if c == "LOGIN" {
				t.Fatal("bare LOGIN token must not be advertised (not a capability; RFC 3501 uses LOGINDISABLED for the inverse)")
			}
			if c == "LITERAL+" {
				t.Fatal("LITERAL+ must not be advertised: pre-auth literals are bounded, LITERAL- is the honest promise")
			}
		}
	})

	t.Run("capability_response_matches_greeting", func(t *testing.T) {
		conn, reader, greeting := dial(t)
		defer conn.Close()

		conn.Write([]byte("A1 CAPABILITY\r\n"))
		var capLine string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "* CAPABILITY ") {
				capLine = strings.TrimPrefix(line, "* CAPABILITY ")
			}
			if strings.HasPrefix(line, "A1 ") {
				break
			}
		}
		if capLine == "" {
			t.Fatal("no untagged CAPABILITY response")
		}
		if got, want := capLine, strings.Join(capsFromBracket(t, greeting), " "); got != want {
			t.Fatalf("CAPABILITY response %q != greeting caps %q", got, want)
		}
	})

	t.Run("every_advertised_auth_mechanism_is_accepted", func(t *testing.T) {
		conn, _, greeting := dial(t)
		conn.Close()

		for _, c := range capsFromBracket(t, greeting) {
			if !strings.HasPrefix(c, "AUTH=") {
				continue
			}
			mech := strings.TrimPrefix(c, "AUTH=")
			t.Run(mech, func(t *testing.T) {
				conn, reader, _ := dial(t)
				defer conn.Close()
				// Wrong password on purpose: we only care that the mechanism is
				// dispatched (NO Authentication failed) rather than rejected as
				// unsupported.
				ir := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00wrong-password"))
				conn.Write([]byte(fmt.Sprintf("A1 AUTHENTICATE %s %s\r\n", mech, ir)))
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				if strings.Contains(line, "only supported mechanism") || strings.Contains(strings.ToUpper(line), "BAD") {
					t.Fatalf("advertised AUTH=%s but AUTHENTICATE %s was refused: %q", mech, mech, strings.TrimSpace(line))
				}
			})
		}
	})

	t.Run("sasl_ir_is_honored", func(t *testing.T) {
		// SASL-IR advertised => AUTHENTICATE PLAIN <initial-response> must work
		// in one round trip, with no "+" continuation.
		conn, reader, _ := dial(t)
		defer conn.Close()

		ir := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
		conn.Write([]byte(fmt.Sprintf("A1 AUTHENTICATE PLAIN %s\r\n", ir)))
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if strings.HasPrefix(line, "+") {
				t.Fatal("SASL-IR advertised but proxy sent a continuation for an initial response")
			}
			if strings.HasPrefix(line, "A1 ") {
				if !strings.HasPrefix(line, "A1 OK") {
					t.Fatalf("SASL-IR AUTHENTICATE PLAIN failed: %s", strings.TrimSpace(line))
				}
				break
			}
		}
	})

	t.Run("literal_minus_is_honored", func(t *testing.T) {
		// LITERAL- advertised => a non-synchronizing literal <= 4096 bytes is
		// accepted with no continuation. Exercised via LOGIN.
		conn, reader, _ := dial(t)
		defer conn.Close()

		payload := fmt.Sprintf("A1 LOGIN {%d+}\r\n%s {%d+}\r\n%s\r\n",
			len(account.Email), account.Email, len(account.Password), account.Password)
		conn.Write([]byte(payload))
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if strings.HasPrefix(line, "+") {
				t.Fatal("LITERAL- advertised but proxy sent a continuation for a {N+} literal")
			}
			if strings.HasPrefix(line, "A1 ") {
				if !strings.HasPrefix(line, "A1 OK") {
					t.Fatalf("non-sync literal LOGIN failed: %s", strings.TrimSpace(line))
				}
				break
			}
		}
	})
}
