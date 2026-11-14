package proxy_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/managesieveproxy"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/userapiproxy"
	"golang.org/x/crypto/bcrypt"
)

// These backends accept the proxy's master login and recipient check. A successful
// front-door login must complete, so a failed backend cannot invalidate the cache
// and accidentally hide the reuse of another network's verdict.
func ipCacheBackend(t *testing.T, protocol string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				switch protocol {
				case "imap":
					fmt.Fprint(conn, "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n")
				case "pop3":
					fmt.Fprint(conn, "+OK ready\r\n")
				case "managesieve":
					fmt.Fprint(conn, "\"SASL\" \"PLAIN\"\r\nOK \"ready\"\r\n")
				case "lmtp":
					fmt.Fprint(conn, "220 backend LMTP ready\r\n")
				}
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					switch protocol {
					case "imap":
						tag, _, _ := strings.Cut(line, " ")
						fmt.Fprintf(conn, "%s OK completed\r\n", tag)
					case "pop3":
						fmt.Fprint(conn, "+OK completed\r\n")
					case "managesieve":
						fmt.Fprint(conn, "OK \"completed\"\r\n")
					case "lmtp":
						fmt.Fprint(conn, "250 completed\r\n")
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

func startIPCacheProxy(t *testing.T, protocol string, lookup *config.RemoteLookupConfig, backend string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr := freeAddr(t)
	cache := config.DefaultLookupCacheConfig()
	switch protocol {
	case "imap":
		s, err := imapproxy.New(ctx, nil, "localhost", imapproxy.ServerOptions{Name: "ip-cache", Addr: addr, RemoteAddrs: []string{backend}, RemoteLookup: lookup, LookupCache: &cache, ConnectTimeout: time.Second, ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted, InsecureAuth: true, MasterSASLUsername: "master", MasterSASLPassword: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = s.Start() }()
		t.Cleanup(func() { _ = s.Stop() })
	case "pop3":
		s, err := pop3proxy.New(ctx, "localhost", addr, nil, pop3proxy.POP3ProxyServerOptions{Name: "ip-cache", RemoteAddrs: []string{backend}, RemoteLookup: lookup, LookupCache: &cache, ConnectTimeout: time.Second, ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted, InsecureAuth: true, MasterSASLUsername: "master", MasterSASLPassword: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = s.Start() }()
		t.Cleanup(func() { _ = s.Stop() })
	case "managesieve":
		s, err := managesieveproxy.New(ctx, nil, "localhost", managesieveproxy.ServerOptions{Name: "ip-cache", Addr: addr, RemoteAddrs: []string{backend}, RemoteLookup: lookup, LookupCache: &cache, ConnectTimeout: time.Second, ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted, InsecureAuth: true, MasterSASLUsername: "master", MasterSASLPassword: "secret"})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = s.Start() }()
		t.Cleanup(func() { _ = s.Stop() })
	case "lmtp":
		s, err := lmtpproxy.New(ctx, nil, "localhost", lmtpproxy.ServerOptions{Name: "ip-cache", Addr: addr, RemoteAddrs: []string{backend}, RemoteLookup: lookup, LookupCache: &cache, ConnectTimeout: time.Second, ProxyProtocol: true, TrustedProxies: trusted})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = s.Start() }()
		t.Cleanup(func() { _ = s.Stop() })
	case "userapi":
		s, err := userapiproxy.New(ctx, nil, userapiproxy.ServerOptions{Name: "ip-cache", Addr: addr, RemoteAddrs: []string{backend}, RemoteLookup: lookup, LookupCache: &cache, JWTSecret: strings.Repeat("x", 32), ProxyProtocol: true, TrustedNetworks: trusted, TrustedProxies: trusted})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = s.Start() }()
		t.Cleanup(func() { _ = s.Stop() })
	}
	return addr
}

func probeIPCacheProxy(t *testing.T, protocol, addr, ip string) string {
	t.Helper()
	conn, r := dialProxiedIP(t, addr, ip)
	defer conn.Close()
	plain := base64.StdEncoding.EncodeToString([]byte("\x00anna@example.com\x00secret"))
	switch protocol {
	case "imap":
		readUntil(t, r, "* OK")
		send(t, conn, "a1 LOGIN anna@example.com secret")
		if strings.HasPrefix(readUntil(t, r, "a1 "), "a1 OK") {
			return "allowed"
		}
	case "pop3":
		readUntil(t, r, "+OK")
		send(t, conn, "USER anna@example.com")
		readUntil(t, r, "+OK", "-ERR")
		send(t, conn, "PASS secret")
		if strings.HasPrefix(readUntil(t, r, "+OK", "-ERR"), "+OK") {
			return "allowed"
		}
	case "managesieve":
		readUntil(t, r, "OK")
		send(t, conn, `AUTHENTICATE "PLAIN" "`+plain+`"`)
		if strings.HasPrefix(readUntil(t, r, "OK", "NO", "BYE"), "OK") {
			return "allowed"
		}
	case "lmtp":
		readUntil(t, r, "220")
		send(t, conn, "LHLO mta.example.org")
		readUntil(t, r, "250 ")
		send(t, conn, "MAIL FROM:<sender@example.org>")
		readUntil(t, r, "2", "4", "5")
		send(t, conn, "RCPT TO:<anna@example.com>")
		if strings.HasPrefix(readUntil(t, r, "2", "4", "5"), "2") {
			return "allowed"
		}
	case "userapi":
		body := `{"email":"anna@example.com","password":"secret"}`
		fmt.Fprintf(conn, "POST /user/auth/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		response, err := http.ReadResponse(r, &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		b, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("HTTP proxy: %d %s", response.StatusCode, b)
		}
		return string(b)
	}
	return "denied"
}

func TestIPDependentLookupDoesNotReuseAnotherNetworksCache(t *testing.T) {
	// Cache policy does not depend on hash cost; keep the wire-level test quick
	// without changing the process-wide password hashing configuration.
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"imap", "pop3", "managesieve", "lmtp", "userapi"} {
		for _, order := range []string{"positive_then_negative", "negative_then_positive", "independent_cache_still_used"} {
			t.Run(protocol+"/"+order, func(t *testing.T) {
				independent := order == "independent_cache_still_used"
				var backend, pinned string
				if protocol == "userapi" {
					// A routing miss uses the normal flat-pool fallback. Distinct
					// bodies expose a cached negative route or a cached positive pin.
					fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "denied") }))
					t.Cleanup(fallback.Close)
					allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "allowed") }))
					t.Cleanup(allowed.Close)
					backend, pinned = strings.TrimPrefix(fallback.URL, "http://"), strings.TrimPrefix(allowed.URL, "http://")
				} else {
					backend = ipCacheBackend(t, protocol)
					pinned = backend
				}
				var calls atomic.Int32
				lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if !independent && r.URL.Query().Get("ip") != "192.0.2.10" {
						if protocol == "userapi" {
							w.WriteHeader(http.StatusNotFound)
						} else {
							w.WriteHeader(http.StatusForbidden)
						}
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"address": "anna@example.com", "password_hash": string(hash), "server": pinned, "account_id": 1})
				}))
				t.Cleanup(lookup.Close)
				url := lookup.URL + "/?email=$email"
				if !independent {
					url += "&ip=$ip"
				}
				cfg := &config.RemoteLookupConfig{Enabled: true, URL: url}
				addr := startIPCacheProxy(t, protocol, cfg, backend)
				ips := []string{"192.0.2.10", "198.51.100.20"}
				if order == "negative_then_positive" {
					ips[0], ips[1] = ips[1], ips[0]
				}
				for _, ip := range ips {
					want := "denied"
					if independent || ip == "192.0.2.10" {
						want = "allowed"
					}
					if got := probeIPCacheProxy(t, protocol, addr, ip); got != want {
						t.Errorf("client %s got %q, want %q", ip, got, want)
					}
				}
				wantCalls := int32(2)
				if independent {
					wantCalls = 1
				}
				if got := calls.Load(); got != wantCalls {
					t.Errorf("lookup requests=%d, want %d", got, wantCalls)
				}
			})
		}
	}
}
