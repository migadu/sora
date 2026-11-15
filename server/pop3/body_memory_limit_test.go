package pop3

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-pop3/pop3server"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
)

// newBodyMemoryTestSession returns a session with the given memory budget, whose
// body cache holds body, and body's message with the given size (0: unknown).
func newBodyMemoryTestSession(t *testing.T, limit int64, body string, size int) (*POP3Session, *serverPkg.SessionMemoryTracker, *db.POP3Message) {
	t.Helper()
	c, err := cache.New(t.TempDir(), 1<<20, 1<<20, time.Hour, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	msg := &db.POP3Message{AccountID: 7, UID: 1, ContentHash: strings.Repeat("a", 64), Size: size, IsUploaded: true}
	path := c.GetPathForContentHash(msg.ContentHash)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	tracker := serverPkg.NewSessionMemoryTracker(limit)
	return &POP3Session{server: &POP3Server{cache: c}, memTracker: tracker}, tracker, msg
}

// requireBodyRefusal fails t unless err is -ERR with code.
func requireBodyRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var perr *pop3server.Error
	if !errors.As(err, &perr) {
		t.Fatalf("error = %v, want -ERR [%s]", err, code)
	}
	if perr.Code != code {
		t.Fatalf("error = -ERR [%s] %s, want -ERR [%s]", perr.Code, perr.Message, code)
	}
}

// TestRetrBodyOverSessionMemoryLimit: RETR and TOP load the whole body into the
// session memory budget (session_memory_limit), beside the session's message
// list. A body that does not fit the whole budget beside the list can never be
// retrieved until an operator raises the limit, which RFC 3206 section 4 gives
// [SYS/PERM]: "problems which are unlikely to be resolved without
// intervention", such as "system configuration errors". [SYS/TEMP] is for a
// budget only short for now ("insufficient free disk or memory"), and a client
// retries it on every check.
func TestRetrBodyOverSessionMemoryLimit(t *testing.T) {
	body := "Subject: memory limit\r\n\r\n" + strings.Repeat("x", 64*1024) + "\r\n"
	for _, tc := range []struct {
		name  string
		limit int64
		list  int64 // charged for the session's message list
		held  int64 // what other data of the session holds
		size  int   // the message's recorded size, 0 when unknown
		code  string
	}{
		{"larger than the budget, size known", 1024, 0, 0, len(body), "SYS/PERM"},
		{"larger than the budget, size unknown", 1024, 0, 0, 0, "SYS/PERM"},
		{"not beside the message list", int64(len(body) + 1024), 2048, 0, len(body), "SYS/PERM"},
		{"budget short for now, size known", int64(2 * len(body)), 2048, int64(3 * len(body) / 2), len(body), "SYS/TEMP"},
		{"budget short for now, size unknown", int64(2 * len(body)), 2048, int64(3 * len(body) / 2), 0, "SYS/TEMP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, tracker, msg := newBodyMemoryTestSession(t, tc.limit, body, tc.size)
			if err := tracker.Allocate(tc.list + tc.held); err != nil {
				t.Fatal(err)
			}
			s.messagesMemBytes = tc.list
			data, err := s.getMessageBody(context.Background(), msg)
			if err == nil {
				t.Fatalf("loaded a %d-byte body into a %d-byte budget holding %d", len(data), tc.limit, tc.list+tc.held)
			}
			requireBodyRefusal(t, err, tc.code)
			if got := tracker.Current(); got != tc.list+tc.held {
				t.Errorf("memory tracker after refusal = %d bytes, want the %d held before", got, tc.list+tc.held)
			}
		})
	}
}
