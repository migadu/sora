package imapproxy

import (
	"net"
	"reflect"
	"testing"
)

// maintenanceCloseLayer is a walkable net.Conn layer that records its Close in
// the shared log and does not forward it, so a test sees which layers the
// forced close hit and in what order.
type maintenanceCloseLayer struct {
	net.Conn
	name  string
	inner net.Conn
	log   *[]string
}

func (l *maintenanceCloseLayer) Unwrap() net.Conn { return l.inner }
func (l *maintenanceCloseLayer) Close() error {
	*l.log = append(*l.log, l.name)
	return nil
}

// maintenanceCloseLeaf is the walk's natural end: a net.Conn with neither
// Unwrap() nor NetConn().
type maintenanceCloseLeaf struct {
	net.Conn
	name string
	log  *[]string
}

func (l *maintenanceCloseLeaf) Close() error {
	*l.log = append(*l.log, l.name)
	return nil
}

// closeMaintenanceTransport closes the socket first, so a stalled close_notify
// cannot hold the grace timer, and then the outer conn for its bookkeeping. A
// bare socket is closed once, and nil is nothing to close.
func TestCloseMaintenanceTransport(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		closeMaintenanceTransport(nil)
	})
	t.Run("bare socket", func(t *testing.T) {
		var log []string
		closeMaintenanceTransport(&maintenanceCloseLeaf{name: "socket", log: &log})
		if want := []string{"socket"}; !reflect.DeepEqual(log, want) {
			t.Fatalf("Close order = %q, want %q", log, want)
		}
	})
	t.Run("socket then outer wrapper", func(t *testing.T) {
		var log []string
		socket := &maintenanceCloseLeaf{name: "socket", log: &log}
		middle := &maintenanceCloseLayer{Conn: socket, name: "middle", inner: socket, log: &log}
		outer := &maintenanceCloseLayer{Conn: middle, name: "outer", inner: middle, log: &log}
		closeMaintenanceTransport(outer)
		if want := []string{"socket", "outer"}; !reflect.DeepEqual(log, want) {
			t.Fatalf("Close order = %q, want %q", log, want)
		}
	})
	t.Run("Unwrap yields nil", func(t *testing.T) {
		var log []string
		closeMaintenanceTransport(&maintenanceCloseLayer{name: "outer", log: &log})
		if want := []string{"outer"}; !reflect.DeepEqual(log, want) {
			t.Fatalf("Close order = %q, want %q", log, want)
		}
	})
}
