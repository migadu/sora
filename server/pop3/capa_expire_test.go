package pop3

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// capaExpire returns the EXPIRE line a server configured with the given
// [cleanup] max_age_restriction advertises in CAPA.
func capaExpire(t *testing.T, maxAge string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, err := New(ctx, "test", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, POP3ServerOptions{
		InsecureAuth:   true,
		CommandTimeout: time.Minute,
		MaxConnections: 10,
		Config:         &config.Config{Cleanup: config.CleanupConfig{MaxAgeRestriction: maxAge}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	go srv.buildLibServer().ServeConn(server)
	client.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(client)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting = %q, %v", line, err)
	}
	fmt.Fprint(client, "CAPA\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("CAPA = %q, %v", line, err)
	}
	expire := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CAPA: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			break
		}
		if strings.HasPrefix(line, "EXPIRE") {
			expire = line
		}
	}
	fmt.Fprint(client, "QUIT\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("QUIT = %q, %v", line, err)
	}
	return expire
}

// EXPIRE is the minimum retention in whole days, or NEVER (RFC 2449 §6.7).
// "EXPIRE 0" means the client may not leave mail on the server, so a positive
// retention shorter than a day must still advertise at least 1 (#1904).
func TestCAPAExpireFromMaxAgeRestriction(t *testing.T) {
	tests := []struct {
		maxAge string
		want   string
	}{
		{"", "EXPIRE NEVER"},
		{"0s", "EXPIRE NEVER"},
		{"1h", "EXPIRE 1"},
		{"23h59m", "EXPIRE 1"},
		{"24h", "EXPIRE 1"},
		{"47h", "EXPIRE 1"},
		{"48h", "EXPIRE 2"},
		{"720h", "EXPIRE 30"},
	}
	for _, tt := range tests {
		t.Run(tt.maxAge, func(t *testing.T) {
			if got := capaExpire(t, tt.maxAge); got != tt.want {
				t.Errorf("max_age_restriction %q: CAPA advertises %q, want %q", tt.maxAge, got, tt.want)
			}
		})
	}
}
