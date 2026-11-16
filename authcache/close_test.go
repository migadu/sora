package authcache

import (
	"bytes"
	"context"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes of the logger.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitForCloseToWait waits until a goroutine is blocked in Close waiting for
// the pending last_used updates.
func waitForCloseToWait(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "sync.(*WaitGroup).Wait(") && strings.Contains(g, "authcache.(*Cache).Close(") {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Close never started waiting for the pending last_used update")
}

// A login that hits the cache once Close has begun (a proxy still draining
// its sessions when main closes the cache) must not start a last_used
// update: one that registers as Close's wait ends runs against the closed
// database. The lookup itself still answers.
func TestCloseRefusesLastUsedUpdateOnceBegun(t *testing.T) {
	dbPath := tempDBPath(t)
	ctx := context.Background()
	c, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := c.Put(ctx, "user@example.com", 42, "hash"); err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	// Hold the write lock so that the first hit's update stays pending and
	// Close has to wait for it.
	c.mu.Lock()
	if _, _, err := c.Get(ctx, "user@example.com"); err != nil {
		c.mu.Unlock()
		t.Fatalf("Get() before Close error: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	waitForCloseToWait(t)

	accountID, _, err := c.Get(ctx, "user@example.com")
	c.mu.Unlock()
	if err != nil || accountID != 42 {
		t.Errorf("Get() while Close waits = %d, %v; want 42, nil", accountID, err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	reopened, err := New(dbPath, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("reopening the cache: %v", err)
	}
	defer reopened.Close()
	var hits int64
	if err := reopened.db.QueryRow(`SELECT hit_count FROM auth_cache WHERE address = ?`, "user@example.com").Scan(&hits); err != nil {
		t.Fatalf("reading hit_count: %v", err)
	}
	if hits != 1 {
		t.Fatalf("hit_count = %d, want 1: a last_used update started after Close had begun", hits)
	}
}

// Cache hits racing Close never update the closed database, and, under -race,
// registering an update is ordered with Close's wait.
func TestGetDuringCloseNeverUpdatesClosedDatabase(t *testing.T) {
	logs := &syncBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { logger.Swap(prev) })

	ctx := context.Background()
	for i := 0; i < 50; i++ {
		c, err := New(tempDBPath(t), time.Hour, 24*time.Hour, time.Hour)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		if err := c.Put(ctx, "user@example.com", 42, "hash"); err != nil {
			t.Fatalf("Put() error: %v", err)
		}

		got := make(chan struct{})
		go func() {
			defer close(got)
			// Fails with "database is closed" once Close has closed it;
			// the caller then falls back to PostgreSQL.
			_, _, _ = c.Get(ctx, "user@example.com")
		}()
		time.Sleep(time.Duration(rand.IntN(200)) * time.Microsecond)
		if err := c.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
		<-got
	}

	// An update started after Close runs in its own goroutine; give it time
	// to fail.
	for deadline := time.Now().Add(200 * time.Millisecond); time.Now().Before(deadline); {
		if strings.Contains(logs.String(), "Failed to update last_used") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if out := logs.String(); strings.Contains(out, "Failed to update last_used") {
		t.Fatalf("a last_used update ran against the closed database:\n%s", out)
	}
}
