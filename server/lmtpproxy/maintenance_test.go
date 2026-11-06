package lmtpproxy

import (
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// A held backend connection is in maintenance by the address it is connected to, also when
// the name it was routed by (a remote-lookup alias, say) does not resolve for the check.
func TestBackendInMaintenance_ByTheAddressConnectedTo(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	cm := newLMTPTestConnManager(t, ln.Addr().String(), time.Second)
	m := proxy.NewMaintenance()
	cm.SetMaintenance(m)
	s := &Session{server: &Server{connManager: cm}, backendConn: conn, serverAddr: "backend.invalid:24"}
	if s.backendInMaintenance() {
		t.Fatal("in maintenance with nothing in maintenance")
	}
	m.Set([]string{"127.0.0.1"})
	if !s.backendInMaintenance() {
		t.Fatal("a connection to 127.0.0.1 is not in maintenance with 127.0.0.1 in maintenance")
	}
}
