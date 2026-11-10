package imap

import (
	"net"
	"testing"
	"time"

	serverPkg "github.com/migadu/sora/server"
)

// Construct the same wrapper the listener accepts and inspect the limits actually
// registered with the scheduler, including a throughput-only configuration.
func TestConnConfigHonorsDisabledAbsoluteTimeout(t *testing.T) {
	s := &IMAPServer{}
	s.settings.Store(&reloadableSettings{commandTimeout: time.Hour, minBytesPerMinute: 512})
	cfg := s.connConfig()
	cfg.OnTimeout = nil
	client, peer := net.Pipe()
	defer peer.Close()
	conn := serverPkg.NewSoraConn(client, cfg)
	defer conn.Close()
	checked := conn.CheckedTimeouts()
	if checked.MinBytesPerMinute != 512 {
		t.Errorf("throughput checker is not armed: %+v", checked)
	}
	if checked.Absolute != 0 {
		t.Errorf("disabled absolute timeout became %v", checked.Absolute)
	}
}
