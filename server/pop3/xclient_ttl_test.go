package pop3

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestXCLIENTExpiredTTLClosesConnection(t *testing.T) {
	for _, ttl := range []int{-1, 0, 1, 2} {
		t.Run(fmt.Sprint(ttl), func(t *testing.T) {
			s, addr := newReloadTestServer(t, POP3ServerOptions{TrustedNetworks: []string{"127.0.0.0/8"}, CommandTimeout: time.Minute})
			startListenerTestServer(t, s, addr)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReader(conn)
			if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
				t.Fatalf("greeting = %q, %v", line, err)
			}
			fmt.Fprintf(conn, "XCLIENT ADDR=192.0.2.1 PORT=12345 TTL=%d\r\n", ttl)
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if ttl <= 1 {
				if line != "-ERR Proxy TTL expired\r\n" {
					t.Fatalf("expired TTL response = %q", line)
				}
				if line, err = r.ReadString('\n'); err != io.EOF {
					t.Fatalf("after expired TTL: got %q, %v; want EOF", line, err)
				}
			} else {
				if !strings.HasPrefix(line, "+OK") {
					t.Fatalf("valid TTL response = %q", line)
				}
				fmt.Fprint(conn, "CAPA\r\n")
				if line, err = r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
					t.Fatalf("CAPA after valid TTL = %q, %v", line, err)
				}
			}
		})
	}
}

// A TTL that is not a number is an invalid XCLIENT parameter: the command is refused and
// none of it applied, rather than accepted with the default hop budget. It is not a loop,
// so the connection stays open and a well-formed XCLIENT may still follow.
func TestXCLIENTMalformedTTLIsRejected(t *testing.T) {
	for _, ttl := range []string{"invalid", "", "5x"} {
		t.Run("TTL="+ttl, func(t *testing.T) {
			s, addr := newReloadTestServer(t, POP3ServerOptions{TrustedNetworks: []string{"127.0.0.0/8"}, CommandTimeout: time.Minute})
			startListenerTestServer(t, s, addr)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReader(conn)
			if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
				t.Fatalf("greeting = %q, %v", line, err)
			}
			fmt.Fprintf(conn, "XCLIENT ADDR=192.0.2.1 PORT=12345 TTL=%s\r\n", ttl)
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line != "-ERR Invalid XCLIENT parameters\r\n" {
				t.Fatalf("malformed TTL response = %q", line)
			}
			fmt.Fprint(conn, "XCLIENT ADDR=192.0.2.1 PORT=12345 TTL=5\r\n")
			if line, err = r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
				t.Fatalf("well-formed XCLIENT after the refused one = %q, %v", line, err)
			}
		})
	}
}
