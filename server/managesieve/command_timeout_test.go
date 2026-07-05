package managesieve

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// TestApplyCommandTimeout covers the ctx-wrapping helper: nil timeouts and
// unknown commands are no-ops, configured commands get a deadline.
func TestApplyCommandTimeout(t *testing.T) {
	base := context.Background()

	ctx, cancel := applyCommandTimeout(base, "GETSCRIPT", nil)
	cancel()
	if ctx != base {
		t.Error("nil timeouts: expected original context")
	}

	timeouts := defaultCommandTimeouts()
	ctx, cancel = applyCommandTimeout(base, "NOOP", timeouts)
	cancel()
	if ctx != base {
		t.Error("unknown command: expected original context")
	}

	timeouts.GetScript = 0
	ctx, cancel = applyCommandTimeout(base, "GETSCRIPT", timeouts)
	cancel()
	if ctx != base {
		t.Error("zero timeout (disabled): expected original context")
	}

	timeouts.GetScript = 5 * time.Second
	ctx, cancel = applyCommandTimeout(base, "GETSCRIPT", timeouts)
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("configured command: expected a deadline on the context")
	}
}

// TestCommandTimeoutsOverridesWiring verifies New() starts from defaults and
// applies operator overrides from the options.
func TestCommandTimeoutsOverridesWiring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockRDB := &resilient.ResilientDatabase{} // Never dereferenced: no connections are served
	srv, err := New(ctx, "test", "localhost", "127.0.0.1:0", mockRDB, ManageSieveServerOptions{
		MaxConnections: 10,
		CommandTimeoutOverrides: map[string]time.Duration{
			"getscript": 7 * time.Second,
			"putscript": 0, // explicit disable
		},
		Config: &config.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	if srv.commandTimeouts.GetScript != 7*time.Second {
		t.Errorf("GetScript = %v, want 7s (override)", srv.commandTimeouts.GetScript)
	}
	if srv.commandTimeouts.PutScript != 0 {
		t.Errorf("PutScript = %v, want 0 (disabled by override)", srv.commandTimeouts.PutScript)
	}
	if srv.commandTimeouts.ListScripts != DefaultCommandTimeouts().ListScripts {
		t.Errorf("ListScripts = %v, want %v (default preserved)", srv.commandTimeouts.ListScripts, DefaultCommandTimeouts().ListScripts)
	}
}

// TestCommandTimeoutDeadlineFires verifies the wrapped context actually
// expires: a blocked command waiting on ctx.Done() would be released within
// the configured bound.
func TestCommandTimeoutDeadlineFires(t *testing.T) {
	timeouts := defaultCommandTimeouts()
	timeouts.GetScript = 10 * time.Millisecond

	ctx, cancel := applyCommandTimeout(context.Background(), "GETSCRIPT", timeouts)
	defer cancel()

	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("ctx.Err() = %v, want DeadlineExceeded", ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("per-command deadline never fired")
	}
}

// TestCommandContextAbortsCommand drives a real session method with a
// cancelled command context: CHECKSCRIPT must abort with the session-closed
// error instead of proceeding, proving the session logic honours the
// per-command context it is handed.
func TestCommandContextAbortsCommand(t *testing.T) {
	addr, err := server.NewAddress("test@example.com")
	if err != nil {
		t.Fatalf("NewAddress failed: %v", err)
	}

	session := &ManageSieveSession{
		Session: server.Session{
			User: server.NewUser(addr, 123),
		},
		authenticated: true,
		ctx:           context.Background(),
		server: &ManageSieveServer{
			maxScriptSize:       1024,
			supportedExtensions: []string{"fileinto"},
			commandTimeouts:     defaultCommandTimeouts(),
		},
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := session.CheckScript(cancelled, "keep;"); !errors.Is(err, errSessionClosed) {
		t.Errorf("CheckScript with cancelled command context: got %v, want errSessionClosed", err)
	}

	// Same script passes with a live context.
	if _, err := session.CheckScript(context.Background(), "keep;"); err != nil {
		t.Errorf("CheckScript with live context: unexpected error: %v", err)
	}
}
