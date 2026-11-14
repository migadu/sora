package lmtp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

func newShutdownTestBackend(t *testing.T, ctx context.Context, addr string) *LMTPServerBackend {
	t.Helper()
	b, err := New(ctx, "shutdown-start", "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, LMTPServerOptions{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

// startBackend runs Start and returns a channel closed when it returns, and
// the channel it reports errors on.
func startBackend(b *LMTPServerBackend) (<-chan struct{}, chan error) {
	done := make(chan struct{})
	errChan := make(chan error, 1)
	go func() {
		defer close(done)
		b.Start(errChan)
	}()
	return done, errChan
}

// waitStartReturned fails the test unless Start has returned, without
// reporting an error, within a few seconds.
func waitStartReturned(t *testing.T, done <-chan struct{}, errChan chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Start still serving 3s after shutdown")
	}
	select {
	case err := <-errChan:
		t.Fatalf("Start reported %v on shutdown", err)
	default:
	}
}

// cmd/sora closes the LMTP server from a watcher on the application context,
// which races Start, as it does for the proxies (#823). go-smtp's Close closes
// only the listeners Serve has registered, so a listener Start created after
// it was served until the process exited. A shutdown before Start must leave
// nothing listening.
func TestShutdownBeforeStartDoesNotServe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	b := newShutdownTestBackend(t, ctx, addr)
	cancel()
	b.Close() // what cmd/sora's watcher does on ctx.Done
	done, errChan := startBackend(b)
	waitStartReturned(t, done, errChan)

	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatalf("%s accepts connections after a shutdown that came before Start", addr)
	}
}

// Shutdown at varying points of Start: before, while and after it creates the
// listener and hands it to go-smtp.
func TestShutdownRacingStartEndsStart(t *testing.T) {
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		b := newShutdownTestBackend(t, ctx, "127.0.0.1:0")
		done, errChan := startBackend(b)
		time.Sleep(time.Duration(i) * 100 * time.Microsecond)
		cancel()
		b.Close()
		waitStartReturned(t, done, errChan)
	}
}
