package imap

import (
	"context"
	"math"
	"testing"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// newAppendLimitTestServer builds a server with the given append_limit and
// session_memory_limit, and a session whose memory budget is taken from the
// server's settings the way newSession takes it.
func newAppendLimitTestServer(t *testing.T, appendLimit, sessionMemoryLimit int64) (*IMAPServer, *IMAPSession) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv, err := New(ctx, "append-limit", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, IMAPServerOptions{
		AppendLimit:        appendLimit,
		SessionMemoryLimit: sessionMemoryLimit,
		MaxConnections:     10,
		Config:             &config.Config{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, newAppendLimitTestSession(srv)
}

func newAppendLimitTestSession(srv *IMAPServer) *IMAPSession {
	return &IMAPSession{server: srv, memTracker: serverPkg.NewSessionMemoryTracker(srv.settings.Load().sessionMemoryLimit)}
}

// An append_limit larger than the largest message sora can store must be
// clamped, not wrapped or advertised as is. RFC 7889 section 5: "The number
// indicates the fixed maximum message size in octets that the server will
// accept." messages.size and pending_uploads.size are INTEGER columns, so a
// message above 2,147,483,647 octets is refused by the database whatever the
// APPENDLIMIT said (#492). The clamp also keeps the value inside the RFC 3501
// "number" (0 <= n < 4,294,967,296) that APPENDLIMIT is written as: converting
// 4 GiB with uint32() wrapped it to 0, which advertised APPENDLIMIT=0 and
// refused every APPEND with NO [TOOBIG] (#333).
func TestAppendLimitAbove32BitsIsClamped(t *testing.T) {
	const gib = int64(1) << 30
	tests := []struct {
		name       string
		configured int64
		want       uint32
	}{
		{"4gb", 4 * gib, math.MaxInt32},
		{"5gb", 5 * gib, math.MaxInt32},
		{"max uint32", math.MaxUint32, math.MaxInt32},
		{"just below 4gb", 4*gib - 2, math.MaxInt32},
		{"2gb", 2 * gib, math.MaxInt32},
		{"max int32", math.MaxInt32, math.MaxInt32},
		{"just below 2gb", math.MaxInt32 - 1, math.MaxInt32 - 1},
		{"default when unset", 0, DefaultAppendLimit},
		{"25mb", DefaultAppendLimit, DefaultAppendLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// session_memory_limit 0: an unlimited budget, so only append_limit counts.
			_, sess := newAppendLimitTestServer(t, tt.configured, 0)
			if got := sess.AppendLimit(); got != tt.want {
				t.Errorf("AppendLimit() with append_limit=%d = %d, want %d", tt.configured, got, tt.want)
			}
		})
	}
}

// APPEND reads the whole literal into memory charged to the session memory
// budget (readAppendLiteral), so a message larger than session_memory_limit
// is never accepted. The APPENDLIMIT a session advertises and enforces must
// therefore not exceed its budget, or a message under the advertised limit is
// answered NO [UNAVAILABLE] "please try again later", which never succeeds
// (#492).
func TestAppendLimitCappedBySessionMemory(t *testing.T) {
	const mb = int64(1) << 20
	tests := []struct {
		name               string
		appendLimit        int64
		sessionMemoryLimit int64
		want               uint32
	}{
		{"budget below append_limit", 25 * mb, 1 * mb, uint32(1 * mb)},
		{"budget below the default", 0, 1 * mb, uint32(1 * mb)},
		{"budget below a 4gb append_limit", 4 << 30, 100 * mb, uint32(100 * mb)},
		{"budget equal to append_limit", 25 * mb, 25 * mb, uint32(25 * mb)},
		{"budget above append_limit", 25 * mb, 100 * mb, uint32(25 * mb)},
		{"unlimited budget", 25 * mb, 0, uint32(25 * mb)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, sess := newAppendLimitTestServer(t, tt.appendLimit, tt.sessionMemoryLimit)
			if got := sess.AppendLimit(); got != tt.want {
				t.Errorf("AppendLimit() with append_limit=%d, session_memory_limit=%d = %d, want %d",
					tt.appendLimit, tt.sessionMemoryLimit, got, tt.want)
			}
		})
	}
}

// session_memory_limit is reloaded on SIGHUP for the sessions started after
// the reload, and append_limit is not: the APPENDLIMIT must follow each
// session's own budget, not a value computed once at startup.
func TestAppendLimitFollowsReloadedSessionMemory(t *testing.T) {
	const mb = int64(1) << 20
	srv, before := newAppendLimitTestServer(t, 25*mb, 100*mb)

	if err := srv.ReloadConfig(config.ServerConfig{
		Limits: &config.ServerLimitsConfig{SessionMemoryLimit: "1mb"},
	}); err != nil {
		t.Fatalf("ReloadConfig: %v", err)
	}
	after := newAppendLimitTestSession(srv)

	if got, want := after.AppendLimit(), uint32(1*mb); got != want {
		t.Errorf("AppendLimit() of a session started after session_memory_limit was reloaded to 1mb = %d, want %d", got, want)
	}
	if got, want := before.AppendLimit(), uint32(25*mb); got != want {
		t.Errorf("AppendLimit() of a session started before the reload = %d, want %d (its budget is still 100mb)", got, want)
	}
}
