package userapiproxy

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
	"golang.org/x/net/dns/dnsmessage"
)

// phase zero: a.test -> .1 and b.test -> .2. Phase one moves a.test
// to .3 and b.test to .1 atomically, without an overlapping ownership snapshot.
func poolTransferDNS(t *testing.T) *atomic.Bool {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	phase := new(atomic.Bool)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			var last byte
			switch q.Name.String() {
			case "a.transfer.test.":
				if phase.Load() {
					last = 3
				} else {
					last = 1
				}
			case "b.transfer.test.":
				if phase.Load() {
					last = 1
				} else {
					last = 2
				}
			}
			if last != 0 && q.Type == dnsmessage.TypeA {
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AResource{A: [4]byte{127, 0, 0, last}})
			}
			response, err := b.Finish()
			if err == nil {
				conn.WriteTo(response, peer)
			}
		}
	}()
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = old; conn.Close(); <-done })
	return phase
}

type poolTransferLookup struct{ scriptedLookup }

func (*poolTransferLookup) LookupUserRouteWithOptions(_ context.Context, email, _ string, _ bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	pool := "a"
	if strings.HasPrefix(email, "b@") {
		pool = "b"
	}
	return &proxy.UserRoutingInfo{PoolName: pool}, proxy.AuthSuccess, nil
}

func TestUserAPITLSReuseStaysWithPoolAfterDNSOwnershipChange(t *testing.T) {
	for _, inFlight := range []bool{false, true} {
		name := "idle"
		if inFlight {
			name = "in_flight"
		}
		t.Run(name, func(t *testing.T) {
			phase := poolTransferDNS(t)
			var hits atomic.Int32
			addresses := make(chan string, 8)
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				addresses <- r.RemoteAddr
				if hits.Add(1) == 1 && inFlight {
					close(entered)
					<-release
				}
				w.WriteHeader(http.StatusTeapot)
			}))
			certA, certB := selfSignedCert(t), selfSignedCert(t)
			backend.TLS = &tls.Config{Certificates: []tls.Certificate{certA}}
			backend.StartTLS()
			t.Cleanup(backend.Close)
			caA, caB := filepath.Join(t.TempDir(), "a.pem"), filepath.Join(t.TempDir(), "b.pem")
			for file, der := range map[string][]byte{caA: certA.Certificate[0], caB: certB.Certificate[0]} {
				if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, port, err := net.SplitHostPort(backend.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			s, err := New(context.Background(), nil, ServerOptions{Name: "pool-transfer", JWTSecret: strings.Repeat("x", 32), Pools: []proxy.PoolSpec{
				{Name: "a", Backends: []string{net.JoinHostPort("a.transfer.test", port)}, Settings: proxy.BackendSettings{TLS: true, TLSVerify: true, TLSCAFile: caA}},
				{Name: "b", Backends: []string{net.JoinHostPort("b.transfer.test", port)}, Settings: proxy.BackendSettings{TLS: true, TLSVerify: true, TLSCAFile: caB}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				s.cancel()
				for _, tr := range s.transports {
					tr.CloseIdleConnections()
				}
			})
			s.routingLookup = &poolTransferLookup{}
			handler := s.setupHandler()
			firstDone := make(chan int, 1)
			go func() { firstDone <- login(handler, `{"email":"a@example.com"}`) }()
			if inFlight {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("A request did not reach backend")
				}
			} else {
				if code := <-firstDone; code != http.StatusTeapot {
					t.Fatalf("warm A connection: %d", code)
				}
				firstAddr := <-addresses
				if code := login(handler, `{"email":"a@example.com"}`); code != http.StatusTeapot {
					t.Fatalf("reuse within A: %d", code)
				}
				if reused := <-addresses; reused != firstAddr {
					t.Fatalf("same-pool requests stopped reusing TCP: %s != %s", reused, firstAddr)
				}
			}
			phase.Store(true)
			if err := s.connManager.ResolveAddresses(); err != nil {
				t.Fatal(err)
			}
			addr := net.JoinHostPort("127.0.0.1", port)
			if !s.connManager.PoolHasBackend("b", addr) || s.connManager.PoolHasBackend("a", addr) {
				t.Fatal("ownership did not transfer exclusively to B")
			}
			fresh, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, s.connManager.BackendClientTLS(true, addr))
			if fresh != nil {
				fresh.Close()
			}
			if err == nil {
				t.Fatal("B's CA unexpectedly trusted the A endpoint")
			}
			if inFlight {
				if code := login(handler, `{"email":"b@example.com"}`); code != http.StatusBadGateway {
					t.Fatalf("fresh B request: %d", code)
				}
				close(release)
				if code := <-firstDone; code != http.StatusTeapot {
					t.Fatalf("complete A request: %d", code)
				}
			}
			if code := login(handler, `{"email":"b@example.com"}`); code != http.StatusBadGateway {
				t.Fatalf("B reused an A TLS connection: status=%d backend_requests=%d", code, hits.Load())
			}
			want := int32(2)
			if inFlight {
				want = 1
			}
			if got := hits.Load(); got != want {
				t.Fatalf("requests reaching A=%d want %d", got, want)
			}
		})
	}
}
