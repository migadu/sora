package lmtp

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// SIGHUP runs ReloadConfig on its own goroutine while deliveries run. DATA reads
// max_message_size (and debug, further down, past the database) for every message.
func TestReloadConfig_DuringData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := New(ctx, "reload", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, LMTPServerOptions{
		MaxMessageSize: 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sender, _ := server.NewAddress("sender@example.com")
	rcpt, _ := server.NewAddress("user@example.com")
	s := &LMTPSession{backend: b, ctx: ctx, startTime: time.Now(), sender: &sender}
	s.Protocol = "LMTP"
	s.User = server.NewUser(rcpt, 1)
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, ctx, "LMTP", nil)

	cfgs := []config.ServerConfig{
		{Name: "reload", Type: "lmtp", MaxMessageSize: "2kb", Debug: true},
		{Name: "reload", Type: "lmtp", MaxMessageSize: "1kb"},
	}
	// Larger than either limit, so DATA refuses it before the database.
	body := strings.Repeat("X", 4096)
	reloadWhile(t, b.ReloadConfig, cfgs, func() {
		for i := 0; i < 50; i++ {
			err := s.Data(ctx, strings.NewReader(body))
			if se, ok := err.(*smtp.SMTPError); !ok || se.Code != 552 {
				t.Fatalf("DATA over the limit: %v, want 552", err)
			}
		}
	})

	// And a reload takes effect for the deliveries after it: the refusal names the limit.
	if err := b.ReloadConfig(config.ServerConfig{Name: "reload", Type: "lmtp", MaxMessageSize: "3kb"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Data(ctx, strings.NewReader(body)); err == nil || !strings.Contains(err.Error(), "of 3072 bytes") {
		t.Errorf("DATA after reloading max_message_size = 3kb: %v", err)
	}
}

// reloadWhile runs ReloadConfig every millisecond, alternating cfgs, until work returns.
func reloadWhile(t *testing.T, reload func(config.ServerConfig) error, cfgs []config.ServerConfig, work func()) {
	t.Helper()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := reload(cfgs[i%len(cfgs)]); err != nil {
				t.Errorf("ReloadConfig: %v", err)
				return
			}
			time.Sleep(time.Millisecond) // still overlapping every reader, without flooding the log
		}
	}()
	work()
	close(stop)
	wg.Wait()
}
