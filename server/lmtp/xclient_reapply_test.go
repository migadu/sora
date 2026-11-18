package lmtp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// NewSession re-applies the XCLIENT attributes go-smtp keeps on the connection to every
// session it creates afterwards. go-smtp records only what it accepted itself: a peer in
// trusted_networks and the six attributes ADDR, PORT, PROTO, HELO, LOGIN and NAME, each
// with a valid value. So an attribute it refuses (TTL among them) is never recorded and
// never reaches a later session, and what it recorded survives RSET and a repeated LHLO.
func TestXCLIENTReappliedAttributesAreWhatGoSMTPRecorded(t *testing.T) {
	newConn := func(t *testing.T) (net.Conn, *bufio.Reader, <-chan *LMTPSession) {
		t.Helper()
		addr, sessions := startXCLIENTBackend(t, LMTPServerOptions{
			TrustedNetworks: []string{"127.0.0.0/8"},
			MaxConnections:  10,
		})
		conn := dialUntilListening(t, addr)
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		if line := lmtpReply(t, r); !strings.HasPrefix(line, "220 ") {
			t.Fatalf("greeting = %q", line)
		}
		return conn, r, sessions
	}
	send := func(t *testing.T, conn net.Conn, r *bufio.Reader, cmd, wantPrefix string) {
		t.Helper()
		fmt.Fprintf(conn, "%s\r\n", cmd)
		if line := lmtpReply(t, r); !strings.HasPrefix(line, wantPrefix) {
			t.Fatalf("%s = %q, want %q...", cmd, line, wantPrefix)
		}
	}
	nextSession := func(t *testing.T, sessions <-chan *LMTPSession) *LMTPSession {
		t.Helper()
		select {
		case s := <-sessions:
			return s
		case <-time.After(3 * time.Second):
			t.Fatal("session was not created")
			return nil
		}
	}

	t.Run("recorded identity survives RSET and a repeated LHLO", func(t *testing.T) {
		conn, r, sessions := newConn(t)
		send(t, conn, r, "LHLO mta.example.org", "250 ")
		nextSession(t, sessions)
		send(t, conn, r, "XCLIENT ADDR=203.0.113.7 HELO=mx.example.org", "220 ")
		send(t, conn, r, "LHLO mta.example.org", "250 ")
		afterXCLIENT := nextSession(t, sessions)
		send(t, conn, r, "RSET", "250 ")
		send(t, conn, r, "LHLO mta.example.org", "250 ")
		afterReLHLO := nextSession(t, sessions)

		for name, s := range map[string]*LMTPSession{"after XCLIENT": afterXCLIENT, "after RSET and LHLO": afterReLHLO} {
			if s.RemoteIP != "203.0.113.7" {
				t.Errorf("session %s: client address = %q, want the forwarded 203.0.113.7", name, s.RemoteIP)
			}
			if s.ForwardingParams == nil || s.ForwardingParams.HELO != "mx.example.org" {
				t.Errorf("session %s lost the forwarded HELO: %+v", name, s.ForwardingParams)
			}
		}
	})

	for _, ttl := range []string{"5", "invalid"} {
		t.Run("XCLIENT with TTL="+ttl+" is refused and nothing of it recorded", func(t *testing.T) {
			conn, r, sessions := newConn(t)
			send(t, conn, r, "LHLO mta.example.org", "250 ")
			nextSession(t, sessions)
			send(t, conn, r, "XCLIENT ADDR=203.0.113.7 HELO=mx.example.org TTL="+ttl, "501 5.5.4 Invalid XCLIENT attributes: unknown attribute: TTL")
			send(t, conn, r, "LHLO mta.example.org", "250 ")
			s := nextSession(t, sessions)
			if s.RemoteIP != "127.0.0.1" || s.ProxyIP != "" || s.ForwardingParams != nil {
				t.Errorf("refused XCLIENT reached the next session: client %q, proxy %q, params %+v", s.RemoteIP, s.ProxyIP, s.ForwardingParams)
			}
		})
	}
}
