package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// newUpgradeableConn returns a SoraConn as a STARTTLS listener's library
// registers it: the provider reports no upgraded connection. upgraded is what
// the provider returns, for a test to swap in as the library would.
func newUpgradeableConn(t *testing.T, config SoraConnConfig) (sc *SoraConn, peer net.Conn, upgraded *net.Conn) {
	t.Helper()
	transport, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	config.NoAbsoluteTimeout = true
	sc = NewSoraConn(transport, config)
	t.Cleanup(func() { sc.Close() })
	upgraded = new(net.Conn)
	SetTimeoutNoticeConn(sc, func() net.Conn { return *upgraded })
	return sc, peer, upgraded
}

// libraryReads has the client send each chunk and the library read it off the
// SoraConn, one Read per chunk, on the calling goroutine.
func libraryReads(t *testing.T, sc *SoraConn, peer net.Conn, chunks ...string) {
	t.Helper()
	for _, chunk := range chunks {
		go peer.Write([]byte(chunk))
		if _, err := io.ReadFull(sc, make([]byte, len(chunk))); err != nil {
			t.Fatalf("reading %q: %v", chunk, err)
		}
	}
}

// A session that never sends STARTTLS on a STARTTLS listener (insecure_auth, or
// simply before the upgrade) reads in plaintext, so a shutdown notice in
// plaintext is exactly what it must get (#236). Only a negotiation in progress
// leaves no safe writer.
func TestNoticeConnOnPlaintextSessionOfStartTLSListener(t *testing.T) {
	sc, peer, _ := newUpgradeableConn(t, SoraConnConfig{})
	if got := NoticeConn(sc); got != sc {
		t.Fatalf("NoticeConn before any command = %v, want the plaintext connection", got)
	}
	libraryReads(t, sc, peer, "CAPA\r\n", "USER someone\r\n", "PASS secret\r\n")
	for name, conn := range map[string]net.Conn{"SoraConn": sc, "wrapper": unwrapConn{sc}} {
		if got := NoticeConn(conn); got != conn {
			t.Errorf("NoticeConn(%s) on a plaintext session = %v, want the connection given", name, got)
		}
	}
}

// The timeout notice of the same plaintext session goes to the transport.
func TestTimeoutNoticeReachesPlaintextSessionOfStartTLSListener(t *testing.T) {
	sc, peer, _ := newUpgradeableConn(t, SoraConnConfig{
		IdleTimeout: time.Minute,
		OnTimeout:   func(conn net.Conn, reason string) { fmt.Fprintf(conn, "goodbye %s\r\n", reason) },
	})
	libraryReads(t, sc, peer, "USER someone\r\n")

	sc.checkTimeouts(time.Now().Add(time.Hour))
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, _ := io.ReadAll(peer)
	if want := "goodbye idle\r\n"; string(got) != want {
		t.Fatalf("timeout notice on a plaintext session = %q, want %q", got, want)
	}
}

// From the moment the library has read a STARTTLS command it may acknowledge
// it, and from the acknowledgement on the client expects TLS: there is no safe
// writer until the library publishes its TLS connection. A refused STARTTLS
// leaves the session plaintext, which the next command shows.
func TestNoticeConnAcrossStartTLSCommand(t *testing.T) {
	const clientHello = "\x16\x03\x01\x02\x00\x01\x00"
	tests := []struct {
		name      string
		chunks    []string
		plaintext bool // a plaintext notice is safe after the chunks
	}{
		{"POP3 STLS", []string{"STLS\r\n"}, false},
		{"ManageSieve and LMTP STARTTLS", []string{"STARTTLS\r\n"}, false},
		{"IMAP tagged STARTTLS", []string{"a1 STARTTLS\r\n"}, false},
		{"lower case", []string{"a1 starttls\r\n"}, false},
		{"bare LF", []string{"STLS\n"}, false},
		{"after other commands in one read", []string{"CAPA\r\nSTLS\r\n"}, false},
		{"split across reads", []string{"ST", "LS\r", "\n"}, false},
		{"ClientHello follows", []string{"STLS\r\n", clientHello}, false},
		{"handshake continues", []string{"STLS\r\n", clientHello, "\x00\x00\x00\x00"}, false},
		{"other command", []string{"NOOP\r\n"}, true},
		{"command in progress", []string{"STL"}, true},
		{"refused: pipelined in one read", []string{"STLS\r\nCAPA\r\n"}, true},
		{"refused: plaintext command follows", []string{"STLS\r\n", "CAPA\r\n"}, true},
		{"refused, then accepted", []string{"STLS\r\nCAPA\r\n", "STLS\r\n"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, peer, _ := newUpgradeableConn(t, SoraConnConfig{})
			libraryReads(t, sc, peer, tt.chunks...)
			got := NoticeConn(sc)
			if tt.plaintext && got != sc {
				t.Errorf("NoticeConn = %v, want the plaintext connection", got)
			}
			if !tt.plaintext && got != nil {
				t.Errorf("NoticeConn = %T, want none while STARTTLS may be negotiating", got)
			}
		})
	}
}

// Once the library publishes its TLS connection the notice goes there, also
// when the session had been suppressed by the STARTTLS command.
func TestNoticeConnAfterStartTLSCompletes(t *testing.T) {
	sc, peer, upgraded := newUpgradeableConn(t, SoraConnConfig{})
	libraryReads(t, sc, peer, "STLS\r\n", "\x16\x03\x01\x02\x00")
	tlsConn := &noticeRecordingConn{Conn: sc}
	*upgraded = tlsConn
	libraryReads(t, sc, peer, "\x17\x03\x03\x00\x10")
	if got := NoticeConn(sc); got != tlsConn {
		t.Fatalf("NoticeConn after the upgrade = %T, want the library's connection", got)
	}
}

// go-imap publishes its *tls.Conn before the handshake has run. Until the
// handshake completes that connection is not a writer for a notice from
// another goroutine: a Write on it would run the server handshake there (#236).
func TestNoticeConnOmitsUnhandshakedTLSConn(t *testing.T) {
	sc, _, upgraded := newUpgradeableConn(t, SoraConnConfig{})
	*upgraded = tls.Server(sc, &tls.Config{})
	sc.recordNoticeConn() // as the handshake's first Read does
	for _, conn := range []net.Conn{sc, unwrapConn{sc}} {
		if got := NoticeConn(conn); got != nil {
			t.Fatalf("NoticeConn with an unhandshaked TLS connection = %T, want none", got)
		}
	}
}
