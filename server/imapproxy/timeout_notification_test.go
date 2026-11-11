package imapproxy

import (
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// A timeout notice must not keep the shard from checking its other connections.
// net.Pipe makes client backpressure deterministic without filling a TCP buffer.
// The callback is the one the production IMAP proxy installs on accepted sockets.
func TestTimeoutNoticeDoesNotBlockOtherConnections(t *testing.T) {
	scheduler := &server.TimeoutScheduler{}
	if err := scheduler.Start(1, 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	blocked, unread := net.Pipe()
	other, otherPeer := net.Pipe()
	t.Cleanup(func() {
		unread.Close()
		otherPeer.Close()
		blocked.Close()
		other.Close()
		scheduler.Stop()
	})
	s := &Server{}
	s.settings.Store(&reloadableSettings{absoluteSessionTimeout: 30 * time.Millisecond})
	cfg := s.connConfig()
	cfg.EnableTimeoutChecker = false // register in this isolated scheduler
	stall := server.NewSoraConn(blocked, cfg)
	otherCfg := s.connConfig()
	otherCfg.EnableTimeoutChecker = false
	otherCfg.AbsoluteTimeout = 100 * time.Millisecond
	expired := make(chan struct{}, 1)
	otherCfg.OnTimeout = func(net.Conn, string) {
		select {
		case expired <- struct{}{}:
		default:
		}
	}
	victim := server.NewSoraConn(other, otherCfg)
	scheduler.Register(stall)
	scheduler.Register(victim)
	select {
	case <-expired:
	case <-time.After(time.Second):
		t.Fatal("unrelated session timeout was not enforced: timeout notice to an unread peer blocked the scheduler shard")
	}
}
