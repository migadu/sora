package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
)

// startStartTLSThroughputServer serves ManageSieve on a tls_use_starttls
// listener with the slowloris check armed to fire in well under a second. It
// runs the accept loop itself, as Start does, only to shorten the throughput
// clock of the connections it accepts; the library server, its NewSession and
// the connection configuration are the server's own.
func startStartTLSThroughputServer(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, err := New(ctx, "test", "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		TLS:               true,
		TLSUseStartTLS:    true,
		TLSCertFile:       "../../testdata/sora.crt",
		TLSKeyFile:        "../../testdata/sora.key",
		MinBytesPerMinute: 1 << 40,     // any trickle is "too slow"
		CommandTimeout:    time.Minute, // the library's idle timer must not fire first
		MaxConnections:    10,
		Config:            &config.Config{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	lib := srv.msLibServer.Load()

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := serverPkg.NewSoraListenerFunc(tcp, func() serverPkg.SoraConnConfig {
		cfg := srv.connConfig()
		cfg.ThroughputWindow = 200 * time.Millisecond
		cfg.ThroughputGrace = time.Millisecond
		return cfg
	})
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go lib.ServeConn(conn)
		}
	}()
	return tcp.Addr().String()
}

// readUntilOK consumes a capability block up to and including its OK line.
func readUntilOK(t *testing.T, reader *bufio.Reader, what string) {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if strings.HasPrefix(line, "OK") {
			return
		}
		if strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
			t.Fatalf("%s: %q", what, line)
		}
	}
}

// trickle feeds the slowloris signature, bytes that never complete a command,
// until stopped or the connection goes away.
func trickle(conn net.Conn) (stop func()) {
	quit := make(chan struct{})
	done := make(chan struct{})
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
	return func() { close(quit); <-done }
}

// A client that upgraded with STARTTLS must read the slow-throughput BYE
// through TLS. go-managesieve layers its TLS connection ABOVE the SoraConn, so
// a notice written to the SoraConn's transport is plaintext inside the TLS
// stream: the client gets a TLS record error in place of the BYE line (#163).
func TestSlowThroughputNoticeAfterStartTLSIsReadableThroughTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}
	addr := startStartTLSThroughputServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	readUntilOK(t, reader, "greeting")
	fmt.Fprint(conn, "STARTTLS\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "OK") {
		t.Fatalf("STARTTLS = %q, %v", line, err)
	}
	if n := reader.Buffered(); n != 0 {
		t.Fatalf("%d plaintext bytes after the STARTTLS OK, before the handshake", n)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	tlsReader := bufio.NewReader(tlsConn)
	readUntilOK(t, tlsReader, "capabilities after STARTTLS") // RFC 5804 §2.2
	defer trickle(tlsConn)()

	line, err := tlsReader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the timeout notice through TLS: %v", err)
	}
	if want := "BYE (TRYLATER) \"Connection too slow, please reconnect\"\r\n"; line != want {
		t.Fatalf("timeout notice through TLS = %q, want %q", line, want)
	}
	if _, err := tlsReader.ReadString('\n'); err == nil {
		t.Fatal("connection stayed open after the timeout notice")
	}
}
