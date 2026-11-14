package imap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"

	serverPkg "github.com/migadu/sora/server"
)

// newProxiedIDTestServer serves a database-free IMAPServer behind a PROXY listener that
// accepts headers from 127.0.0.1, a layer-4 load balancer. trustedNetworks is the
// server's trusted_networks, which decides who may forward client parameters with ID.
func newProxiedIDTestServer(t *testing.T, trustedNetworks []string) string {
	t.Helper()
	appCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &IMAPServer{
		name:        "id-proxy-trust",
		hostname:    "id-proxy-trust",
		appCtx:      appCtx,
		caps:        imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapID: {}},
		activeConns: make(map[*imapserver.Conn]struct{}),
		limiter:     serverPkg.NewConnectionLimiterWithTrustedNets("IMAP", 0, 0, trustedNetworks),
	}
	srv.settings.Store(&reloadableSettings{})
	var golog syncLogBuffer
	is := imapserver.New(&imapserver.Options{
		NewSession:   srv.newSession,
		Logger:       log.New(&golog, "", 0),
		InsecureAuth: true,
		Caps:         srv.caps,
	})
	reader, err := serverPkg.NewProxyProtocolReader("IMAP", serverPkg.ProxyProtocolConfig{
		Enabled:        true,
		Mode:           "required",
		TrustedProxies: []string{"127.0.0.1/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go is.Serve(serverPkg.WrapProxyProtocol(ln, reader, "IMAP"))
	t.Cleanup(func() { is.Close() })
	return ln.Addr().String()
}

// sendProxiedID connects as the load balancer relaying a client at clientIP, sends an ID
// that forwards 203.0.113.5 as the client address, then LOGOUT, and returns everything
// the server answered after the greeting.
func sendProxiedID(t *testing.T, addr, clientIP string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "PROXY TCP4 %s 127.0.0.1 51000 143\r\n", clientIP)
	r := bufio.NewReader(c)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	c.Write([]byte(`a ID ("name" "client" "x-originating-ip" "203.0.113.5" "x-proxy-ttl" "5")` + "\r\n"))
	c.Write([]byte("b LOGOUT\r\n"))
	rest, err := io.ReadAll(r)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("no LOGOUT within 3s; server sent:\n%s", rest)
	}
	if !strings.Contains(string(rest), "a OK") || !strings.Contains(string(rest), "b OK") {
		t.Fatalf("ID and LOGOUT were not both answered:\n%s", rest)
	}
	return string(rest)
}

// The PROXY header's sender (a layer-4 load balancer) is trusted to say who the client is,
// not to vouch for the commands after the header: those are the client's own. So an ID
// forwarding a client address is honoured only when the header's source is itself trusted,
// a proxy behind the load balancer. Judging the sender let any client behind it pick the
// address the auth rate limiter and the per-IP connection limits count.
func TestIDForwardingTrustedByProxyHeaderSource(t *testing.T) {
	// trusted_networks lists the load balancer (127.0.0.1) and a proxy behind it (127.0.0.2).
	trusted := []string{"127.0.0.1/32", "127.0.0.2/32"}
	for _, tc := range []struct {
		name, clientIP string
		applied        bool
	}{
		{"untrusted client behind trusted load balancer", "198.51.100.66", false},
		{"trusted proxy behind trusted load balancer", "127.0.0.2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := newProxiedIDTestServer(t, trusted)

			rest := sendProxiedID(t, addr, tc.clientIP)
			if got := strings.Contains(rest, "203.0.113.5"); got != tc.applied {
				t.Errorf("forwarded client address applied = %v, want %v:\n%s", got, tc.applied, rest)
			}
		})
	}
}

// After login the peer relays the client's commands (an imap_proxy does), so an ID then
// is the client's and must not change the address the session was established with.
func TestIDForwardingIgnoredAfterAuthentication(t *testing.T) {
	srv := &IMAPServer{
		name:     "id-after-auth",
		hostname: "id-after-auth",
		appCtx:   context.Background(),
		caps:     imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapID: {}},
		limiter:  serverPkg.NewConnectionLimiterWithTrustedNets("IMAP", 0, 0, []string{"127.0.0.0/8"}),
	}
	srv.settings.Store(&reloadableSettings{})
	addr, err := serverPkg.NewAddress("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	s := &IMAPSession{server: srv, ctx: context.Background()}
	s.Protocol = "IMAP"
	// Established through a trusted proxy that sent a PROXY header for 198.51.100.20.
	s.RemoteIP = "198.51.100.20"
	s.ProxyIP = "127.0.0.1"
	s.IMAPUser = NewIMAPUser(addr, 42)
	s.Session.User = &s.IMAPUser.User

	s.ID(&imap.IDData{Name: "client", Raw: map[string]string{
		"name":             "client",
		"x-originating-ip": "203.0.113.20",
		"x-proxy-ttl":      "5",
	}})

	if s.RemoteIP != "198.51.100.20" {
		t.Errorf("RemoteIP = %q after an ID following login, want the established 198.51.100.20", s.RemoteIP)
	}
	if s.ForwardingParams != nil {
		t.Errorf("forwarding parameters applied after login: %+v", s.ForwardingParams)
	}
}
