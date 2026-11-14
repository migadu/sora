package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// proxyProtocolListener starts one server type through the function startServers
// dispatches it to, and checks that the protocol, not the PROXY header, is the first
// thing the server reads.
type proxyProtocolListener struct {
	start     func(context.Context, *serverDependencies, config.ServerConfig, chan error)
	configure func(*config.ServerConfig) // what the type needs besides type, name and addr
	probe     func(t *testing.T, r *bufio.Reader, w io.Writer)
}

// The client the load balancer names in its PROXY header.
const proxiedClientIP = "192.0.2.10"

var proxyProtocolListeners = map[string]proxyProtocolListener{
	"imap":              {start: startDynamicIMAPServer, probe: textProbe("* OK", "a1 NOOP", "a1 OK")},
	"pop3":              {start: startDynamicPOP3Server, probe: textProbe("+OK", "CAPA", "+OK")},
	"managesieve":       {start: startDynamicManageSieveServer, probe: textProbe("OK", "NOOP", "OK")},
	"lmtp":              {start: startDynamicLMTPServer, probe: textProbe("220 ", "NOOP", "250 ")},
	"imap_proxy":        {start: startDynamicIMAPProxyServer, configure: withRemoteAddrs, probe: textProbe("* OK", "a1 NOOP", "a1 OK")},
	"pop3_proxy":        {start: startDynamicPOP3ProxyServer, configure: withRemoteAddrs, probe: textProbe("+OK", "CAPA", "+OK")},
	"managesieve_proxy": {start: startDynamicManageSieveProxyServer, configure: withRemoteAddrs, probe: textProbe("OK", "NOOP", "OK")},
	"lmtp_proxy":        {start: startDynamicLMTPProxyServer, configure: withRemoteAddrs, probe: textProbe("220 ", "NOOP", "250 ")},
	// allowed_hosts names only the proxied client: the request passes the host check
	// only if the server took the client address from the PROXY header.
	"http_admin_api": {
		start: startDynamicHTTPAdminAPIServer,
		configure: func(sc *config.ServerConfig) {
			sc.APIKey = "test-admin-api-key-0123456789"
			sc.AllowedHosts = []string{proxiedClientIP + "/32"}
		},
		probe: httpProbe("/admin/health/overview", http.StatusUnauthorized),
	},
	"http_user_api": {
		start: startDynamicHTTPUserAPIServer,
		configure: func(sc *config.ServerConfig) {
			sc.JWTSecret = "test-jwt-secret-0123456789abcdef"
			sc.AllowedHosts = []string{proxiedClientIP + "/32"}
		},
		probe: httpProbe("/user/mailboxes", http.StatusUnauthorized),
	},
	"user_api_proxy": {
		start: startDynamicUserAPIProxyServer,
		configure: func(sc *config.ServerConfig) {
			withRemoteAddrs(sc)
			sc.JWTSecret = "test-jwt-secret-0123456789abcdef"
		},
		probe: httpProbe("/user/mailboxes", http.StatusUnauthorized),
	},
}

// proxyProtocolServerTypes are the [[server]] types the configuration accepts.
var proxyProtocolServerTypes = []string{"imap", "lmtp", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "metrics", "http_admin_api", "http_user_api", "user_api_proxy"}

// Server types whose listener does not read PROXY headers. Startup must say so when
// proxy_protocol is set on one, and must not require trusted_networks for it.
var withoutProxyProtocol = map[string]bool{"metrics": true}

// TestProxyProtocolReachesEveryListener walks every [[server]] type the configuration
// accepts and sets proxy_protocol = true on it (#272). Each listener that reads PROXY
// headers must take the header from a peer in [servers] trusted_networks before its
// protocol starts, and must refuse one from a peer outside it. The imap_proxy,
// pop3_proxy, managesieve_proxy, lmtp_proxy and http_admin_api blocks used to drop the
// setting, so the header reached the protocol as client data.
func TestProxyProtocolReachesEveryListener(t *testing.T) {
	for _, serverType := range proxyProtocolServerTypes {
		t.Run(serverType, func(t *testing.T) {
			sc := config.ServerConfig{Type: serverType, Name: serverType + "-pp", ProxyProtocol: true}

			if withoutProxyProtocol[serverType] {
				var warnings []string
				sc.WarnUnusedConfigOptions(func(format string, args ...any) {
					warnings = append(warnings, fmt.Sprintf(format, args...))
				})
				if !strings.Contains(strings.Join(warnings, "\n"), "'proxy_protocol'") {
					t.Errorf("proxy_protocol = true on a %s block is ignored without a warning; warnings: %q", serverType, warnings)
				}
				cfg := config.Config{DynamicServers: []config.ServerConfig{sc}}
				if missing := cfg.ProxyProtocolListenersMissingTrust(); len(missing) != 0 {
					t.Errorf("startup requires trusted_networks for %v, whose listener does not read PROXY headers", missing)
				}
				return
			}

			l, ok := proxyProtocolListeners[serverType]
			if !ok {
				t.Fatalf("no PROXY protocol probe for server type %q", serverType)
			}
			if l.configure != nil {
				l.configure(&sc)
			}

			t.Run("trusted peer", func(t *testing.T) {
				conn := startWithProxyProtocol(t, l, sc, []string{"127.0.0.0/8"})
				r := bufio.NewReader(conn)
				l.probe(t, r, conn)
			})

			// The header travels in plaintext ahead of the TLS ClientHello, so the
			// listener must read it from the raw connection before the handshake.
			t.Run("trusted peer, implicit TLS", func(t *testing.T) {
				tlsServer := sc
				tlsServer.TLS = true
				tlsServer.TLSCertFile = "../../testdata/sora.crt"
				tlsServer.TLSKeyFile = "../../testdata/sora.key"
				conn := tls.Client(startWithProxyProtocol(t, l, tlsServer, []string{"127.0.0.0/8"}), &tls.Config{InsecureSkipVerify: true})
				if err := conn.Handshake(); err != nil {
					t.Fatalf("TLS handshake after a PROXY header: %v", err)
				}
				l.probe(t, bufio.NewReader(conn), conn)
			})

			t.Run("untrusted peer", func(t *testing.T) {
				conn := startWithProxyProtocol(t, l, sc, []string{"192.0.2.1/32"})
				buf := make([]byte, 512)
				n, err := conn.Read(buf)
				if n > 0 || err == nil {
					t.Fatalf("server answered a PROXY header from 127.0.0.1, which is outside trusted_networks: %q", buf[:n])
				}
				if isTimeout(err) {
					t.Fatalf("server kept the connection of an untrusted PROXY peer open: %v", err)
				}
			})
		})
	}
}

// startWithProxyProtocol starts sc on a free loopback port with the given
// trusted_networks, connects, and sends a PROXY v1 header naming proxiedClientIP.
func startWithProxyProtocol(t *testing.T, l proxyProtocolListener, sc config.ServerConfig, trusted []string) net.Conn {
	t.Helper()
	sc.Addr = freeLoopbackAddr(t)

	cfg := config.NewDefaultConfig()
	cfg.Servers.TrustedNetworks = trusted
	cfg.DynamicServers = []config.ServerConfig{sc}
	deps := &serverDependencies{
		storage:            &storage.S3Storage{},
		resilientDB:        &resilient.ResilientDatabase{},
		uploadWorker:       &uploader.UploadWorker{},
		cacheInstance:      &cache.Cache{},
		hostname:           "localhost",
		config:             cfg,
		serverManager:      &serverManager{},
		connectionTrackers: make(map[string]*server.ConnectionTracker),
		proxyServers:       make(map[string]adminapi.ProxyServer),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.start(ctx, deps, sc, errChan)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("%s server did not stop", sc.Type)
		}
	})

	for deadline := time.Now().Add(5 * time.Second); ; {
		select {
		case err := <-errChan:
			t.Fatalf("%s server failed to start: %v", sc.Type, err)
		default:
		}
		if c, err := net.Dial("tcp", sc.Addr); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s server did not listen on %s", sc.Type, sc.Addr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := net.DialTimeout("tcp", sc.Addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", sc.Addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, port, _ := net.SplitHostPort(sc.Addr)
	if _, err := fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 40000 %s\r\n", proxiedClientIP, port); err != nil {
		t.Fatalf("write PROXY header: %v", err)
	}
	return conn
}

// textProbe reads the greeting up to its line starting with greetingEnd, sends
// command, and requires the next line to start with ok. Had the server not read the
// PROXY header, that line would be its answer to "PROXY TCP4 ...", an error.
func textProbe(greetingEnd, command, ok string) func(*testing.T, *bufio.Reader, io.Writer) {
	return func(t *testing.T, r *bufio.Reader, w io.Writer) {
		t.Helper()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("reading the greeting after a PROXY header: %v (read %q)", err, line)
			}
			if strings.HasPrefix(line, greetingEnd) {
				break
			}
		}
		if _, err := fmt.Fprintf(w, "%s\r\n", command); err != nil {
			t.Fatalf("write %s: %v", command, err)
		}
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the answer to %s: %v", command, err)
		}
		if !strings.HasPrefix(line, ok) {
			t.Fatalf("first answer after the greeting = %q, want the answer to %s (%q...): the PROXY header reached the protocol as client data", strings.TrimRight(line, "\r\n"), command, ok)
		}
	}
}

// httpProbe sends a GET for path and requires the status want. Had the server not
// read the PROXY header, net/http would answer 400 to the request line "PROXY TCP4 ...";
// had it read it without taking the client address from it, allowed_hosts would answer 403.
func httpProbe(path string, want int) func(*testing.T, *bufio.Reader, io.Writer) {
	return func(t *testing.T, r *bufio.Reader, w io.Writer) {
		t.Helper()
		if _, err := fmt.Fprintf(w, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path); err != nil {
			t.Fatalf("write request: %v", err)
		}
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatalf("reading the response after a PROXY header: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("GET %s after a PROXY header = %s, want %d", path, resp.Status, want)
		}
	}
}

func withRemoteAddrs(sc *config.ServerConfig) {
	// A backend that is never dialed: every probe is answered before login.
	sc.RemoteAddrs = []string{"192.0.2.20:1"}
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
