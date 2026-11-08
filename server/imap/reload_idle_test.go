package imap

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/config"
	serverPkg "github.com/migadu/sora/server"
)

// A reload landing between a connection's accept and its session (during its TLS
// handshake, say) must not move the IDLE keepalive off the idle timeout the
// connection's checker enforces, which its listener gave it at the accept.
func TestReloadConfig_IdleKeepaliveFollowsTheConnectionsChecker(t *testing.T) {
	srv, _ := newReloadTestServer(t, IMAPServerOptions{CommandTimeout: 2 * time.Minute})
	sessions := make(chan *IMAPSession, 1)
	is := imapserver.New(&imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			if err := srv.ReloadConfig(config.ServerConfig{Name: "reload", Type: "imap", Timeouts: &config.ServerTimeoutsConfig{CommandTimeout: "30m"}}); err != nil {
				return nil, nil, err
			}
			sess, greeting, err := srv.newSession(c)
			if err == nil {
				sessions <- sess.(*meteredSession).IMAPSession
			}
			return sess, greeting, err
		},
		Logger:       log.New(io.Discard, "", 0),
		InsecureAuth: true,
		Caps:         srv.caps,
	})
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go is.Serve(serverPkg.NewSoraListenerFunc(base, srv.connConfig))
	t.Cleanup(func() { is.Close() })

	c, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case sess := <-sessions:
		if sess.checkedIdleTimeout != 2*time.Minute {
			t.Errorf("IDLE keepalive set from %v, want the connection's checker's 2m (reload to 30m after the accept)", sess.checkedIdleTimeout)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no session")
	}
}
