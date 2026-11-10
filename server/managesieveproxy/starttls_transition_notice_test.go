package managesieveproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// Exercise the proxy's own library session callback and connection policy with
// a real socket. No authentication or backend is needed to stall STARTTLS.
func startTransitionNoticeProxy(t *testing.T, throughput bool) (*Server, string) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Server{
		ctx: ctx, name: "transition-notice", hostname: "localhost",
		tls: true, tlsUseStartTLS: true,
		tlsConfig:      &tls.Config{Certificates: []tls.Certificate{cert}},
		activeSessions: make(map[*Session]struct{}),
	}
	settings := &reloadableSettings{commandTimeout: time.Minute}
	if throughput {
		settings.minBytesPerMinute = 1 << 40
	}
	s.settings.Store(settings)
	lib := s.buildLibServer()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	wrapped := server.NewSoraListenerFunc(listener, func() server.SoraConnConfig {
		cfg := s.connConfig()
		cfg.ThroughputWindow = 200 * time.Millisecond
		cfg.ThroughputGrace = time.Millisecond
		return cfg
	})
	go func() {
		for {
			conn, err := wrapped.Accept()
			if err != nil {
				return
			}
			go lib.ServeConn(conn)
		}
	}()
	return s, listener.Addr().String()
}

func stallTransitionNoticeHandshake(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "OK") {
			break
		}
	}
	fmt.Fprint(conn, "STARTTLS\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "OK") {
		t.Fatalf("STARTTLS = %q, %v", line, err)
	}
	// A TLS handshake record header with its promised payload missing. The
	// library blocks inside HandshakeContext and still publishes plaintext.
	if _, err := conn.Write([]byte{0x16, 0x03, 0x03, 0x10, 0x00}); err != nil {
		t.Fatal(err)
	}
	return conn, reader
}

func assertTransitionNoticeClosedWithoutPlaintext(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	got, err := io.ReadAll(reader)
	if len(got) != 0 {
		t.Fatalf("plaintext during STARTTLS handshake: %q", got)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("STARTTLS transport was not closed: %v", err)
	}
}

func TestManageSieveProxyThroughputDuringSTARTTLSHandshakeOmitsNotice(t *testing.T) {
	_, addr := startTransitionNoticeProxy(t, true)
	conn, reader := stallTransitionNoticeHandshake(t, addr)
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
				if _, err := conn.Write([]byte("N")); err != nil {
					return
				}
			}
		}
	}()
	defer func() { close(quit); <-done }()
	assertTransitionNoticeClosedWithoutPlaintext(t, reader)
}

func TestManageSieveProxyShutdownDuringSTARTTLSHandshakeOmitsNotice(t *testing.T) {
	s, addr := startTransitionNoticeProxy(t, false)
	_, reader := stallTransitionNoticeHandshake(t, addr)
	stopped := make(chan any, 1)
	go func() {
		defer func() { stopped <- recover() }()
		s.sendGracefulShutdownBye()
	}()
	assertTransitionNoticeClosedWithoutPlaintext(t, reader)
	select {
	case panicValue := <-stopped:
		if panicValue != nil {
			t.Fatalf("shutdown panicked during STARTTLS handshake: %v", panicValue)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not complete")
	}
}
