package imapproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// maintenanceWriteSignalConn reports an attempted transport write. After the TLS
// handshake this lets a test wait for close_notify to be blocked on the peer.
type maintenanceWriteSignalConn struct {
	net.Conn
	writing chan struct{}
}

func (c *maintenanceWriteSignalConn) Write(p []byte) (int, error) {
	select {
	case c.writing <- struct{}{}:
	default:
	}
	return c.Conn.Write(p)
}

// stalledMaintenanceTLSBackend completes a real handshake, then leaves the
// backend unread. net.Pipe models a full TCP send buffer without relying on the
// platform's buffer size or on filling it with a large APPEND.
func stalledMaintenanceTLSBackend(t *testing.T) (*tls.Conn, <-chan struct{}) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	proxyRaw, backendRaw := net.Pipe()
	t.Cleanup(func() { proxyRaw.Close(); backendRaw.Close() })
	signal := &maintenanceWriteSignalConn{Conn: proxyRaw, writing: make(chan struct{}, 1)}
	backend := tls.Server(backendRaw, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	conn := tls.Client(signal, &tls.Config{InsecureSkipVerify: true})
	handshake := make(chan error, 1)
	go func() { handshake <- backend.Handshake() }()
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	<-signal.writing // discard the handshake's write notification
	return conn, signal.writing
}

func maintenanceTLSSession(t *testing.T, backend net.Conn) (*Session, net.Conn) {
	t.Helper()
	clientProxy, clientPeer := net.Pipe()
	t.Cleanup(func() { clientProxy.Close(); clientPeer.Close() })
	return &Session{server: &Server{}, backendConn: backend, clientConn: clientProxy, listenerConn: clientProxy}, clientPeer
}

func TestMaintenanceTLS_StalledHalfCloseDoesNotBlockOtherSessions(t *testing.T) {
	backend, writing := stalledMaintenanceTLSBackend(t)
	session, _ := maintenanceTLSSession(t, backend)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := proxy.NewMaintenance()
	secondClosed := make(chan struct{})
	proxy.StartSessionDrainer(ctx, m, 1000, func() []proxy.DrainTarget {
		return []proxy.DrainTarget{
			{Backend: "127.0.0.1:143", Close: session.closeForMaintenance},
			{Backend: "127.0.0.1:143", Close: func() { close(secondClosed) }},
		}
	}, nil, "test")
	m.Set([]string{"127.0.0.1"})
	select {
	case <-writing:
	case <-time.After(time.Second):
		t.Fatal("maintenance never attempted the TLS half-close")
	}
	select {
	case <-secondClosed:
	case <-time.After(time.Second):
		t.Fatal("a stalled TLS half-close blocked the next drain target despite kick_rate=1000")
	}
}

func TestMaintenanceTLS_GraceBoundsStalledHalfClose(t *testing.T) {
	withCloseGrace(t, 200*time.Millisecond)
	backend, writing := stalledMaintenanceTLSBackend(t)
	session, client := maintenanceTLSSession(t, backend)
	go session.closeForMaintenance()
	select {
	case <-writing:
	case <-time.After(time.Second):
		t.Fatal("maintenance never attempted the TLS half-close")
	}
	// No command can finish through this unread backend. The grace deadline must
	// end the session, including when TLS Close itself would wait for CloseWrite.
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(client); err != nil {
		t.Fatalf("client still open past the maintenance grace while TLS CloseWrite is blocked: %v", err)
	}
}
