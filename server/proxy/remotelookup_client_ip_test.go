package proxy_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/managesieveproxy"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapiproxy"
)

// The client every test connects as, announced in a PROXY v1 header by the load
// balancer at 127.0.0.1 (a trusted network).
const proxiedClientIP = "192.0.2.10"

// ipLookup is a remote lookup endpoint recording the ip parameter of each request.
type ipLookup struct {
	*httptest.Server
	mu     sync.Mutex
	ips    []string
	answer func(w http.ResponseWriter) // nil: 404, user not found
}

func newIPLookup(t *testing.T) *ipLookup {
	t.Helper()
	l := &ipLookup{}
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.ips = append(l.ips, r.URL.Query().Get("ip"))
		answer := l.answer
		l.mu.Unlock()
		if answer == nil {
			http.NotFound(w, r)
			return
		}
		answer(w)
	}))
	t.Cleanup(l.Close)
	return l
}

func (l *ipLookup) config() *config.RemoteLookupConfig {
	return &config.RemoteLookupConfig{Enabled: true, URL: l.URL + "/lookup?email=$email&ip=$ip"}
}

// waitIPs returns the recorded ip parameters once there is at least one.
func (l *ipLookup) waitIPs(t *testing.T) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		ips := append([]string(nil), l.ips...)
		l.mu.Unlock()
		if len(ips) > 0 || time.Now().After(deadline) {
			return ips
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertLookupIP(t *testing.T, l *ipLookup) {
	t.Helper()
	ips := l.waitIPs(t)
	if len(ips) == 0 {
		t.Fatal("the remote lookup was never asked")
	}
	for i, ip := range ips {
		if ip != proxiedClientIP {
			t.Errorf("lookup request %d: ip=%q, want %q (the client named in the PROXY header)", i+1, ip, proxiedClientIP)
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// dialProxied connects to addr as a trusted load balancer forwarding proxiedClientIP.
func dialProxied(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err = net.Dial("tcp", addr)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, port, _ := net.SplitHostPort(addr)
	if _, err := fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 51000 %s\r\n", proxiedClientIP, port); err != nil {
		t.Fatalf("write PROXY header: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

func send(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
		t.Fatalf("write %q: %v", line, err)
	}
}

// readUntil reads lines until one starts with one of the prefixes and returns it.
func readUntil(t *testing.T, r *bufio.Reader, prefixes ...string) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read (waiting for %q): %v", prefixes, err)
		}
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) {
				return line
			}
		}
	}
}

var trusted = []string{"127.0.0.0/8"}

func startIMAPProxy(t *testing.T, rl *config.RemoteLookupConfig, backends []string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr := freeAddr(t)
	s, err := imapproxy.New(ctx, &resilient.ResilientDatabase{}, "localhost", imapproxy.ServerOptions{
		Name: "ip", Addr: addr, RemoteAddrs: backends, RemoteLookup: rl, ConnectTimeout: 2 * time.Second,
		ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted, InsecureAuth: true,
		MasterSASLUsername: "master", MasterSASLPassword: "master-secret",
	})
	if err != nil {
		t.Fatalf("imapproxy.New: %v", err)
	}
	go func() { _ = s.Start() }()
	t.Cleanup(func() { _ = s.Stop() })
	return addr
}

// TestRemoteLookupGetsTheProxiedClientIP: every proxy fills the lookup URL's $ip with
// the real client, the source address of the PROXY header, and never sends the
// placeholder itself.
func TestRemoteLookupGetsTheProxiedClientIP(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00anna@example.com\x00secret"))

	t.Run("imap", func(t *testing.T) {
		lookup := newIPLookup(t)
		conn, r := dialProxied(t, startIMAPProxy(t, lookup.config(), []string{"127.0.0.1:1"}))
		readUntil(t, r, "* OK")
		send(t, conn, "a1 LOGIN anna@example.com secret")
		readUntil(t, r, "a1 ")
		assertLookupIP(t, lookup)
	})

	t.Run("pop3", func(t *testing.T) {
		lookup := newIPLookup(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr := freeAddr(t)
		s, err := pop3proxy.New(ctx, "localhost", addr, &resilient.ResilientDatabase{}, pop3proxy.POP3ProxyServerOptions{
			Name: "ip", RemoteAddrs: []string{"127.0.0.1:1"}, RemoteLookup: lookup.config(), ConnectTimeout: 2 * time.Second,
			ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted, InsecureAuth: true,
		})
		if err != nil {
			t.Fatalf("pop3proxy.New: %v", err)
		}
		go func() { _ = s.Start() }()
		defer s.Stop()
		conn, r := dialProxied(t, addr)
		readUntil(t, r, "+OK")
		send(t, conn, "USER anna@example.com")
		readUntil(t, r, "+OK", "-ERR")
		send(t, conn, "PASS secret")
		readUntil(t, r, "+OK", "-ERR")
		assertLookupIP(t, lookup)
	})

	t.Run("managesieve", func(t *testing.T) {
		lookup := newIPLookup(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr := freeAddr(t)
		s, err := managesieveproxy.New(ctx, &resilient.ResilientDatabase{}, "localhost", managesieveproxy.ServerOptions{
			Name: "ip", Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, RemoteLookup: lookup.config(), ConnectTimeout: 2 * time.Second,
			ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted, InsecureAuth: true,
		})
		if err != nil {
			t.Fatalf("managesieveproxy.New: %v", err)
		}
		go func() { _ = s.Start() }()
		defer s.Stop()
		conn, r := dialProxied(t, addr)
		readUntil(t, r, "OK")
		send(t, conn, `AUTHENTICATE "PLAIN" "`+plain+`"`)
		readUntil(t, r, "OK", "NO", "BYE")
		assertLookupIP(t, lookup)
	})

	t.Run("lmtp", func(t *testing.T) {
		lookup := newIPLookup(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr := freeAddr(t)
		s, err := lmtpproxy.New(ctx, &resilient.ResilientDatabase{}, "localhost", lmtpproxy.ServerOptions{
			Name: "ip", Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, RemoteLookup: lookup.config(), ConnectTimeout: 2 * time.Second,
			ProxyProtocol: true, TrustedProxies: trusted,
		})
		if err != nil {
			t.Fatalf("lmtpproxy.New: %v", err)
		}
		go func() { _ = s.Start() }()
		defer s.Stop()
		conn, r := dialProxied(t, addr)
		readUntil(t, r, "220")
		send(t, conn, "LHLO mta.example.org")
		readUntil(t, r, "250 ")
		send(t, conn, "MAIL FROM:<sender@example.org>")
		readUntil(t, r, "2", "4", "5")
		send(t, conn, "RCPT TO:<anna@example.com>")
		readUntil(t, r, "2", "4", "5")
		assertLookupIP(t, lookup)
	})

	t.Run("userapi", func(t *testing.T) {
		lookup := newIPLookup(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr := freeAddr(t)
		s, err := userapiproxy.New(ctx, &resilient.ResilientDatabase{}, userapiproxy.ServerOptions{
			Name: "ip", Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, RemoteLookup: lookup.config(),
			JWTSecret: strings.Repeat("x", 32), ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted,
		})
		if err != nil {
			t.Fatalf("userapiproxy.New: %v", err)
		}
		go func() { _ = s.Start() }()
		defer s.Stop()
		conn, r := dialProxied(t, addr)
		body := `{"email":"anna@example.com","password":"secret"}`
		fmt.Fprintf(conn, "POST /user/auth/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		readUntil(t, r, "HTTP/1.1 ")
		assertLookupIP(t, lookup)
	})
}

// TestIMAPProxyIDForwardsTheProxiedClientIP: the IMAP ID the proxy sends its backend
// (remote_use_id_command) names the client of the PROXY header as x-originating-ip,
// as the POP3 and LMTP XCLIENT forwarding already do.
func TestIMAPProxyIDForwardsTheProxiedClientIP(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	idLine := make(chan string, 1)
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		fmt.Fprint(c, "* OK [CAPABILITY IMAP4rev1 ID AUTH=PLAIN] backend ready\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			tag, rest, _ := strings.Cut(line, " ")
			if strings.HasPrefix(strings.ToUpper(rest), "ID ") {
				select {
				case idLine <- line:
				default:
				}
				fmt.Fprintf(c, "* ID NIL\r\n%s OK ID completed\r\n", tag)
				continue
			}
			fmt.Fprintf(c, "%s NO not in this test\r\n", tag)
		}
	}()

	hash, err := db.GenerateBcryptHash("secret")
	if err != nil {
		t.Fatal(err)
	}
	lookup := newIPLookup(t)
	lookup.answer = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address": "anna@example.com", "password_hash": hash, "server": backend.Addr().String(),
		})
	}
	rl := lookup.config()
	rl.RemoteUseIDCommand = true

	conn, r := dialProxied(t, startIMAPProxy(t, rl, []string{backend.Addr().String()}))
	readUntil(t, r, "* OK")
	send(t, conn, "a1 LOGIN anna@example.com secret")

	select {
	case line := <-idLine:
		want := fmt.Sprintf(`"x-originating-ip" "%s"`, proxiedClientIP)
		if !strings.Contains(line, want) {
			t.Errorf("backend ID command lacks %s:\n%s", want, line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the backend never received an ID command")
	}
}

// TestRemoteLookupWithoutClientIPSendsNoPlaceholder: a lookup made without a client IP
// leaves $ip empty instead of sending the placeholder text to the lookup service.
func TestRemoteLookupWithoutClientIPSendsNoPlaceholder(t *testing.T) {
	var rawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery = r.URL.RawQuery
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := proxy.NewHTTPRemoteLookupClient(srv.URL+"/lookup?email=$email&ip=$ip", 5*time.Second, "", 143,
		false, false, false, false, false, false, false, nil, nil)
	if _, _, err := client.LookupUserRouteWithOptions(context.Background(), "anna@example.com", "", true); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if want := "email=anna%40example.com&ip=&route_only=true"; rawQuery != want {
		t.Errorf("lookup query = %q, want %q", rawQuery, want)
	}
}

// proxyHeaderBackend is a backend that records the source address of the PROXY header
// each connection opens with. A proxy dials it with remote_use_proxy_protocol.
func proxyHeaderBackend(t *testing.T) (addr string, srcIP <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	reader, err := server.NewProxyProtocolReader("TEST-BACKEND", server.ProxyProtocolConfig{Enabled: true, TrustedProxies: trusted})
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 1)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				info, _, err := reader.ReadProxyHeader(c)
				src := "no PROXY header"
				if err == nil && info != nil {
					src = info.SrcIP
				}
				select {
				case ch <- src:
				default:
				}
			}()
		}
	}()
	return l.Addr().String(), ch
}

// pinningLookup answers every lookup with the user, a password hash and backend.
func pinningLookup(t *testing.T, backend string) *config.RemoteLookupConfig {
	t.Helper()
	hash, err := db.GenerateBcryptHash("secret")
	if err != nil {
		t.Fatal(err)
	}
	lookup := newIPLookup(t)
	lookup.answer = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address": "anna@example.com", "password_hash": hash, "server": backend, "account_id": 1,
		})
	}
	rl := lookup.config()
	rl.RemoteUseProxyProtocol = true
	return rl
}

func assertBackendPROXYSource(t *testing.T, srcIP <-chan string) {
	t.Helper()
	select {
	case got := <-srcIP:
		if got != proxiedClientIP {
			t.Errorf("backend PROXY header source = %q, want %q (the client named in the incoming PROXY header)", got, proxiedClientIP)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the backend was never dialed")
	}
}

// TestBackendPROXYHeaderNamesTheProxiedClient: with remote_use_proxy_protocol, the
// PROXY header a proxy sends its backend names the client of the incoming PROXY
// header, not the load balancer the proxy's socket is connected to.
func TestBackendPROXYHeaderNamesTheProxiedClient(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00anna@example.com\x00secret"))

	t.Run("imap", func(t *testing.T) {
		backend, srcIP := proxyHeaderBackend(t)
		conn, r := dialProxied(t, startIMAPProxy(t, pinningLookup(t, backend), []string{backend}))
		readUntil(t, r, "* OK")
		send(t, conn, "a1 LOGIN anna@example.com secret")
		assertBackendPROXYSource(t, srcIP)
	})

	t.Run("pop3", func(t *testing.T) {
		backend, srcIP := proxyHeaderBackend(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr := freeAddr(t)
		s, err := pop3proxy.New(ctx, "localhost", addr, &resilient.ResilientDatabase{}, pop3proxy.POP3ProxyServerOptions{
			Name: "ip", RemoteAddrs: []string{backend}, RemoteLookup: pinningLookup(t, backend), ConnectTimeout: 2 * time.Second,
			ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted, InsecureAuth: true,
		})
		if err != nil {
			t.Fatalf("pop3proxy.New: %v", err)
		}
		go func() { _ = s.Start() }()
		defer s.Stop()
		conn, r := dialProxied(t, addr)
		readUntil(t, r, "+OK")
		send(t, conn, "USER anna@example.com")
		readUntil(t, r, "+OK", "-ERR")
		send(t, conn, "PASS secret")
		assertBackendPROXYSource(t, srcIP)
	})

	t.Run("managesieve", func(t *testing.T) {
		backend, srcIP := proxyHeaderBackend(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr := freeAddr(t)
		s, err := managesieveproxy.New(ctx, &resilient.ResilientDatabase{}, "localhost", managesieveproxy.ServerOptions{
			Name: "ip", Addr: addr, RemoteAddrs: []string{backend}, RemoteLookup: pinningLookup(t, backend), ConnectTimeout: 2 * time.Second,
			ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted, InsecureAuth: true,
		})
		if err != nil {
			t.Fatalf("managesieveproxy.New: %v", err)
		}
		go func() { _ = s.Start() }()
		defer s.Stop()
		conn, r := dialProxied(t, addr)
		readUntil(t, r, "OK")
		send(t, conn, `AUTHENTICATE "PLAIN" "`+plain+`"`)
		assertBackendPROXYSource(t, srcIP)
	})

	t.Run("lmtp", func(t *testing.T) {
		backend, srcIP := proxyHeaderBackend(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr := freeAddr(t)
		s, err := lmtpproxy.New(ctx, &resilient.ResilientDatabase{}, "localhost", lmtpproxy.ServerOptions{
			Name: "ip", Addr: addr, RemoteAddrs: []string{backend}, RemoteLookup: pinningLookup(t, backend), ConnectTimeout: 2 * time.Second,
			ProxyProtocol: true, TrustedProxies: trusted,
		})
		if err != nil {
			t.Fatalf("lmtpproxy.New: %v", err)
		}
		go func() { _ = s.Start() }()
		defer s.Stop()
		conn, r := dialProxied(t, addr)
		readUntil(t, r, "220")
		send(t, conn, "LHLO mta.example.org")
		readUntil(t, r, "250 ")
		send(t, conn, "MAIL FROM:<sender@example.org>")
		readUntil(t, r, "2", "4", "5")
		send(t, conn, "RCPT TO:<anna@example.com>")
		assertBackendPROXYSource(t, srcIP)
	})
}
