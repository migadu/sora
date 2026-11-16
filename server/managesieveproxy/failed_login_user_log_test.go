package managesieveproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

// logBuffer collects what the logger package writes while a test runs.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestManageSieveProxyFailedLoginLogsUser covers #477: the lines logged for a refused
// login name the user who tried it, as the IMAP and POP3 proxies log them. The session
// logger reads s.username, which authenticateUser set only once a login had succeeded,
// so every refusal was logged with user="" and could not be traced to an account.
func TestManageSieveProxyFailedLoginLogsUser(t *testing.T) {
	origCost := db.BcryptCost
	db.BcryptCost = 4
	t.Cleanup(func() { db.BcryptCost = origCost })
	hash, err := db.GenerateBcryptHash("right-password")
	if err != nil {
		t.Fatalf("GenerateBcryptHash: %v", err)
	}
	known := func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"address": "anna@example.com", "password_hash": hash})
	}
	unknown := func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }

	for _, c := range []struct {
		name     string
		username string // as the client submitted it
		answer   http.HandlerFunc
		line     string // the INFO line the refusal logs
		user     string // the user it must name
	}{
		{"wrong password", "anna@example.com", known, "authentication failed", "anna@example.com"},
		{"wrong password with +detail", "anna+sieve@example.com", known, "authentication failed", "anna@example.com"},
		{"address the lookup does not know", "bob@example.com", unknown, "User not found in remotelookup", "bob@example.com"},
	} {
		t.Run(c.name, func(t *testing.T) {
			lookup := httptest.NewServer(c.answer)
			defer lookup.Close()

			// lookup_local_users is off: the lookup service is authoritative.
			srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
				Name: "failed-login-log", Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
				InsecureAuth: true,
				RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer srv.Stop()
			srv.authLimiter = &verdictlessLimiter{}

			logs := &logBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, nil)))
			t.Cleanup(func() { logger.Swap(prev) })

			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sess := &Session{server: srv, clientConn: remote, listenerConn: remote, ctx: ctx, cancel: cancel}

			if err := sess.authenticateUser(c.username, "wrong-password", time.Now()); !errors.Is(err, consts.ErrAuthenticationFailed) {
				t.Fatalf("authenticateUser(%q) with a wrong password = %v, want %v", c.username, err, consts.ErrAuthenticationFailed)
			}

			var line string
			for _, l := range strings.Split(logs.String(), "\n") {
				if strings.Contains(l, c.line) {
					line = l
					break
				}
			}
			if line == "" {
				t.Fatalf("no log line contains %q:\n%s", c.line, logs.String())
			}
			if want := " user=" + c.user + " "; !strings.Contains(line, want) {
				t.Errorf("login as %q refused with\n  %s\nwant it to name%s", c.username, line, want)
			}
		})
	}
}
