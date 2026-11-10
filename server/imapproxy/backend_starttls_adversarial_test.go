package imapproxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// This backend decides whether to negotiate TLS independently of the spelling
// of the status line, so it does not share the proxy's parsing assumption.
func adversarialSTARTTLSBackend(t *testing.T, response func(string) string, offerTLS bool) (string, <-chan string) {
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
		io.WriteString(conn, "* OK backend ready\r\n")
		first, _ := r.ReadString('\n')
		tag, command, _ := strings.Cut(strings.TrimSuffix(first, "\r\n"), " ")
		if command != "STARTTLS" {
			got <- first
			return
		}
		io.WriteString(conn, response(tag))
		if !offerTLS {
			line, _ := r.ReadString('\n')
			got <- line
			return
		}
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if secure.Handshake() != nil {
			got <- ""
			return
		}
		r = bufio.NewReader(secure)
		line, _ := r.ReadString('\n')
		got <- line
		authTag, _, _ := strings.Cut(line, " ")
		io.WriteString(secure, authTag+" OK authenticated\r\n")
	}()
	return ln.Addr().String(), got
}

func TestBackendSTARTTLSAcceptsCaseInsensitiveOKAndUntaggedResponses(t *testing.T) {
	for _, tc := range []struct{ name, before, status string }{
		{"lowercase", "", "ok"},
		{"mixedcase", "", "oK"},
		{"untagged", "* CAPABILITY IMAP4rev1 STARTTLS\r\n* OK informational status\r\n", "OK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, got := adversarialSTARTTLSBackend(t, func(tag string) string { return tc.before + tag + " " + tc.status + " begin TLS\r\n" }, true)
			sess, err := connectThroughSTARTTLS(t, addr)
			if err != nil {
				t.Fatalf("valid STARTTLS response rejected: %v", err)
			}
			if _, err := sess.authenticateToBackend(); err != nil {
				t.Fatal(err)
			}
			if line := <-got; !strings.Contains(line, " AUTHENTICATE PLAIN ") {
				t.Fatalf("TLS backend received %q", line)
			}
		})
	}
}

func TestBackendSTARTTLSRejectsWrongTagsAndMalformedStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response func(string) string
	}{
		{"wrongtag", func(tag string) string { return "other OK begin TLS\r\n" }},
		{"statusprefix", func(tag string) string { return tag + " OKAY not an OK status\r\n" }},
		{"negative", func(tag string) string { return "* OK informational\r\n" + tag + " NO disabled\r\n" }},
		{"statuswithouttext", func(tag string) string { return tag + " OK\r\n" }},
		{"nonasciistatus", func(tag string) string { return tag + " OK begin TLS\r\n" }},
		{"untaggedflood", func(tag string) string {
			return strings.Repeat("* OK informational\r\n", 32) + tag + " OK begin TLS\r\n"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, got := adversarialSTARTTLSBackend(t, tc.response, true)
			sess, err := connectThroughSTARTTLS(t, addr)
			if err == nil {
				sess.authenticateToBackend()
				t.Fatal("accepted invalid STARTTLS completion")
			}
			if line := <-got; line != "" {
				t.Fatalf("credential sent after refused STARTTLS: %q", line)
			}
		})
	}
}
