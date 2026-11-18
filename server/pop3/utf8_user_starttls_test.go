package pop3

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// utf8CapaLines returns the CAPA lines whose capability name is UTF8.
func utf8CapaLines(caps string) []string {
	var lines []string
	for _, c := range strings.Split(caps, "\n") {
		if f := strings.Fields(c); len(f) > 0 && strings.EqualFold(f[0], "UTF8") {
			lines = append(lines, c)
		}
	}
	return lines
}

// TestSTARTTLSListenerAdvertisesUTF8UserOnlyWithUser: RFC 6856 section 2.2's USER
// argument says the USER and PASS commands accept UTF-8. Before STLS on a STARTTLS
// listener with insecure_auth off, USER is not offered, so UTF8 is advertised
// without the argument; after STLS, with USER, it carries it. (#1989)
func TestSTARTTLSListenerAdvertisesUTF8UserOnlyWithUser(t *testing.T) {
	_, addr := startSTARTTLSTestServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting = %q, %v", line, err)
	}
	if got := utf8CapaLines(readCapa(t, conn, r)); strings.Join(got, "|") != "UTF8" {
		t.Errorf("CAPA UTF8 lines before STLS = %q, want [\"UTF8\"]", got)
	}

	fmt.Fprint(conn, "STLS\r\n")
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STLS = %q, %v", line, err)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if got := utf8CapaLines(readCapa(t, tlsConn, bufio.NewReader(tlsConn))); strings.Join(got, "|") != "UTF8 USER" {
		t.Errorf("CAPA UTF8 lines after STLS = %q, want [\"UTF8 USER\"]", got)
	}
}
