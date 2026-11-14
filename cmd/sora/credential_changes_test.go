package main

import (
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/managesieveproxy"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/pop3proxy"
)

// Every server that caches logins, so that a changed account's cached logins are dropped
// from it.
var (
	_ loginCacheHolder = (*imap.IMAPServer)(nil)
	_ loginCacheHolder = (*pop3.POP3Server)(nil)
	_ loginCacheHolder = (*managesieve.ManageSieveServer)(nil)
	_ loginCacheHolder = (*imapproxy.Server)(nil)
	_ loginCacheHolder = (*pop3proxy.POP3ProxyServer)(nil)
	_ loginCacheHolder = (*managesieveproxy.Server)(nil)
)

type fakeCachingServer struct {
	fakeServer
	cache *lookupcache.LookupCache
}

func (f fakeCachingServer) GetLookupCache() *lookupcache.LookupCache { return f.cache }

// The node's login caches are those of the running servers that have one enabled, and
// its session registries are its connection trackers.
func TestCredentialChangesReachEveryRunningServer(t *testing.T) {
	cache := lookupcache.New(time.Minute, time.Minute, 10, time.Minute, time.Minute)
	defer cache.Stop(t.Context())
	tracker := server.NewConnectionTracker("IMAP", "imap", "localhost", "localhost-imap", nil, 0, 0, 0, true)
	defer tracker.Stop()

	deps := &serverDependencies{
		runningServers: map[string]ConfigReloader{
			"imap":     fakeCachingServer{cache: cache},
			"pop3":     fakeCachingServer{}, // lookup cache disabled
			"lmtp":     fakeServer{},
			"adminapi": fakeServer{},
		},
		connectionTrackers: map[string]*server.ConnectionTracker{"IMAP-imap": tracker},
	}

	if caches := deps.loginCaches(); len(caches) != 1 || caches[0] != cache {
		t.Errorf("login caches = %v, want only the IMAP server's", caches)
	}
	if enders := deps.sessionEnders(); len(enders) != 1 || enders[0] != tracker {
		t.Errorf("session enders = %v, want the IMAP tracker", enders)
	}
}
