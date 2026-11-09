package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// startSTLSThroughputServer serves POP3 with STLS available and the slowloris
// check armed to fire in well under a second: the plaintext SoraListener in
// front, the library upgrading the stream on STLS behind it, which is how Start
// wires a tls_use_starttls listener. The test assembles the two halves from the
// server's own connConfig and buildLibServer because Start offers no way to
// shorten the throughput window.
func startSTLSThroughputServer(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, err := New(ctx, "test", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, POP3ServerOptions{
		MinBytesPerMinute: 1 << 40,     // any trickle is "too slow"
		CommandTimeout:    time.Minute, // the library's idle timer must not fire first
		MaxConnections:    10,
		Config:            &config.Config{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	srv.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	lib := srv.buildLibServer()

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

// A client that upgraded with STLS must read the slow-throughput notice
// through TLS. go-pop3 layers its TLS connection ABOVE the SoraConn, so a
// notice written to the SoraConn's transport is plaintext inside the TLS
// stream: the client gets a TLS record error in place of the -ERR line (#163).
func TestSlowThroughputNoticeAfterSTLSIsReadableThroughTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}
	addr := startSTLSThroughputServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting = %q, %v", line, err)
	}
	fmt.Fprint(conn, "STLS\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STLS = %q, %v", line, err)
	}
	if n := reader.Buffered(); n != 0 {
		t.Fatalf("%d plaintext bytes after the STLS +OK, before the handshake", n)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer trickle(tlsConn)()

	tlsReader := bufio.NewReader(tlsConn)
	line, err := tlsReader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the timeout notice through TLS: %v", err)
	}
	if want := "-ERR [IN-USE] Connection too slow, please reconnect\r\n"; line != want {
		t.Fatalf("timeout notice through TLS = %q, want %q", line, want)
	}
	if _, err := tlsReader.ReadString('\n'); err == nil {
		t.Fatal("connection stayed open after the timeout notice")
	}
}
