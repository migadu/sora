//go:build integration

package pop3

import (
	"context"
	"net"

	serverPkg "github.com/migadu/sora/server"
)

// NewSessionForTest returns an unauthenticated session of srv on conn, as the accept
// path creates it, for tests that call its authentication methods directly.
func NewSessionForTest(srv *POP3Server, conn net.Conn) *POP3Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &POP3Session{server: srv, conn: conn, deleted: make(map[int]bool), ctx: ctx, cancel: cancel}
	s.Protocol = "POP3"
	s.ServerName = srv.name
	s.HostName = srv.hostname
	s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, ctx, "POP3", s.InfoLog)
	return s
}
