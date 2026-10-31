package imapproxy

import (
	"net"
	"testing"

	"github.com/migadu/sora/server/proxy"
)

// The drain matches a session by the address its backend connection is connected to, not
// the name it was routed by: a session that reached a backend in maintenance as
// "localhost" is found when maintenance lists the address.
func TestMaintenanceTargets_ReportTheConnectedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	backendConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer backendConn.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	session := &Session{backendConn: backendConn, serverAddr: net.JoinHostPort("localhost", port)}
	s := &Server{activeSessions: map[*Session]struct{}{session: {}}}

	targets := s.MaintenanceTargets()
	if len(targets) != 1 || targets[0].Backend != ln.Addr().String() {
		t.Fatalf("targets = %+v, want one on %s", targets, ln.Addr())
	}
	m := proxy.NewMaintenance()
	m.Set([]string{"127.0.0.1"})
	if !m.Contains(targets[0].Backend) {
		t.Fatal("session on an address in maintenance not matched for the drain")
	}
}
