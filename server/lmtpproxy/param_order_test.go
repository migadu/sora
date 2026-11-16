package lmtpproxy

import (
	"context"
	"strings"
	"testing"
	"time"
)

// When MAIL or RCPT carries more than one parameter refused with different codes, the
// first one refused, in the order the client sent them, decides the reply, on the
// backend and on the proxy alike, every time (#1774). RFC 5321 gives 555 for a parameter
// the server "does not recognize or cannot implement" (section 4.1.1.11) and 501 for a
// "Syntax error in parameters or arguments" (section 4.2.2), and ranks neither above the
// other, but one command must get one reply.
//
// The backend's go-smtp walked the parameters in map order, which Go randomises, so
// SIZE=abc FOO=1 got 501 or 555 from one attempt to the next. The proxy checked SIZE
// after every other parameter, so it answered 555 to both orders. And the backend
// refused an unknown RCPT parameter only after go-smtp had read them all, so FOO=1
// XRCPTFORWARD=!!! got 501 there and 555 on the proxy.
//
// Each command is sent many times: a single attempt could get the right reply by chance.
// The refusals come before any recipient is looked up, so no database is needed.
func TestFirstRefusedParameterDecidesReply(t *testing.T) {
	const repeats = 40
	mailCases := []struct{ params, want string }{
		{"SIZE=abc FOO=1", "501 5.5.4 "},
		{"FOO=1 SIZE=abc", "555 5.5.4 "},
		{"SIZE=99999999999999999999 FOO=1", "552 5.3.4 "},
		{"FOO=1 SIZE=99999999999999999999", "555 5.5.4 "},
		{"SIZE=abc BODY=BINARYMIME", "501 5.5.4 "},
		{"BODY=BINARYMIME SIZE=abc", "555 5.5.4 "},
		{"SMTPUTF8=YES RET=HDRS", "501 5.5.4 "},
		{"RET=HDRS SMTPUTF8=YES", "555 5.5.4 "},
		{"BODY=9BIT RET=HDRS", "501 5.5.4 "},
		{"RET=HDRS BODY=9BIT", "555 5.5.4 "},
		// "=" with no value is refused before any parameter is looked at.
		{"FOO=1 SIZE=", "501 5.5.4 "},
	}
	rcptCases := []struct{ params, want string }{
		{"XRCPTFORWARD=!!! NOTIFY=NEVER", "501 5.5.4 "},
		{"NOTIFY=NEVER XRCPTFORWARD=!!!", "555 5.5.4 "},
		{"XRCPTFORWARD=!!! FOO=1", "501 5.5.4 "},
		{"FOO=1 XRCPTFORWARD=!!!", "555 5.5.4 "},
		{"NOTIFY=NEVER FOO=", "501 5.5.4 "},
	}

	check := func(t *testing.T, send func(string) string) {
		t.Helper()
		for _, tc := range mailCases {
			for i := 0; i < repeats; i++ {
				reply := send("MAIL FROM:<a@example.org> " + tc.params)
				if strings.HasPrefix(reply, "250 ") {
					send("RSET")
				}
				if !strings.HasPrefix(reply, tc.want) {
					t.Errorf("MAIL FROM with %s (attempt %d): %q, want %q", tc.params, i+1, reply, tc.want)
					break
				}
			}
		}
		if reply := send("MAIL FROM:<a@example.org>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("MAIL: %q", reply)
		}
		for _, tc := range rcptCases {
			for i := 0; i < repeats; i++ {
				reply := send("RCPT TO:<b@example.org> " + tc.params)
				if !strings.HasPrefix(reply, tc.want) {
					t.Errorf("RCPT TO with %s (attempt %d): %q, want %q", tc.params, i+1, reply, tc.want)
					break
				}
			}
		}
		send("QUIT")
	}

	backendAddr := startRealSoraLMTPBackend(t, "param-order-backend")
	t.Run("backend", func(t *testing.T) {
		check(t, dialLMTPClient(t, backendAddr))
	})
	t.Run("proxy", func(t *testing.T) {
		srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
			Name:           "param-order-proxy",
			RemoteAddrs:    []string{backendAddr},
			RemotePort:     24,
			ConnectTimeout: 2 * time.Second,
			MaxMessageSize: 52428800,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { srv.Stop() })
		check(t, openProxyPipeSession(t, srv))
	})
}
