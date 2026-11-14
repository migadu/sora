package imap

import (
	"context"
	"math"
	"testing"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// An append_limit that does not fit the 32-bit number of RFC 7889's
// "APPENDLIMIT=" (RFC 3501 number: 0 <= n < 4,294,967,296) must be clamped to
// the largest value IMAP can express, not wrapped: 4 GiB wrapped to 0, which
// advertised APPENDLIMIT=0 and refused every APPEND with NO [TOOBIG] (#333).
func TestAppendLimitAbove32BitsIsClamped(t *testing.T) {
	const gib = int64(1) << 30
	tests := []struct {
		name       string
		configured int64
		want       uint32
	}{
		{"4gb", 4 * gib, math.MaxUint32},
		{"5gb", 5 * gib, math.MaxUint32},
		{"max uint32", math.MaxUint32, math.MaxUint32},
		{"just below 4gb", 4*gib - 2, uint32(4*gib - 2)},
		{"default when unset", 0, DefaultAppendLimit},
		{"25mb", DefaultAppendLimit, DefaultAppendLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv, err := New(ctx, "append-limit", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, IMAPServerOptions{
				AppendLimit:    tt.configured,
				MaxConnections: 10,
				Config:         &config.Config{},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer srv.Close()

			sess := &IMAPSession{server: srv}
			if got := sess.AppendLimit(); got != tt.want {
				t.Errorf("AppendLimit() with append_limit=%d = %d, want %d", tt.configured, got, tt.want)
			}
		})
	}
}
