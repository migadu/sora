package pop3proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// This backend negotiates TLS after any STLS reply, whatever its spelling, so it does
// not share the proxy's parsing assumption. got receives the first line the proxy sent
// after the reply, through TLS ("" when the proxy sent none or never handshook).
func adversarialSTLSBackend(t *testing.T, greeting, reply string) (string, <-chan string) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- ""
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(conn)
		io.WriteString(conn, greeting)
		if line, _ := r.ReadString('\n'); line != "STLS\r\n" {
			got <- line
			return
		}
		io.WriteString(conn, reply)
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if secure.Handshake() != nil {
			got <- ""
			return
		}
		line, _ := bufio.NewReader(secure).ReadString('\n')
		got <- line
		io.WriteString(secure, "+OK logged in\r\n")
	}()
	return ln.Addr().String(), got
}

// The status indicator is case-insensitive (RFC 1939 section 3) and the text after it
// is optional.
func TestBackendSTLSAcceptsCaseInsensitiveOK(t *testing.T) {
	for _, tc := range []struct{ name, greeting, reply string }{
		{"lowercase reply", "+OK ready\r\n", "+ok begin TLS\r\n"},
		{"mixed case reply", "+OK ready\r\n", "+oK begin TLS\r\n"},
		{"reply without text", "+OK ready\r\n", "+OK\r\n"},
		{"lowercase greeting", "+ok ready\r\n", "+OK begin TLS\r\n"},
		{"greeting without text", "+OK\r\n", "+OK begin TLS\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, got := adversarialSTLSBackend(t, tc.greeting, tc.reply)
			if _, err := connectThroughSTLS(t, addr); err != nil {
				t.Fatalf("valid backend response rejected: %v", err)
			}
			if line := <-got; !strings.HasPrefix(line, "AUTH PLAIN ") {
				t.Fatalf("TLS backend received %q, want AUTH PLAIN", line)
			}
		})
	}
}

// +OK is a complete status indicator: a longer word that starts with it is not one.
func TestBackendSTLSRejectsStatusPrefixes(t *testing.T) {
	for _, tc := range []struct{ name, greeting, reply string }{
		{"reply prefix", "+OK ready\r\n", "+OKAY not an OK status\r\n"},
		{"reply prefix lowercase", "+OK ready\r\n", "+okay not an OK status\r\n"},
		{"reply without space", "+OK ready\r\n", "+OK-begin TLS\r\n"},
		{"greeting prefix", "+OKAY not an OK status\r\n", "+OK begin TLS\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, got := adversarialSTLSBackend(t, tc.greeting, tc.reply)
			if _, err := connectThroughSTLS(t, addr); err == nil {
				t.Fatal("accepted a response that is not +OK")
			}
			if line := <-got; line != "" {
				t.Fatalf("the proxy went on after a response that is not +OK and sent %q", line)
			}
		})
	}
}
