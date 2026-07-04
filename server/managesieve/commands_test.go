package managesieve

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/migadu/go-managesieve/managesieveserver"
	"github.com/migadu/sora/server"
)

// TestCheckScript exercises sora's go-sieve validation seam: the wire
// protocol (literals, size bounds) is the library's job, while validation
// failures must render as a quoted "Script validation failed: ..." message.
func TestCheckScript(t *testing.T) {
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
		},
	}

	// Valid script passes with no warnings.
	warnings, err := session.CheckScript(context.Background(), "keep;")
	if err != nil || warnings != "" {
		t.Errorf("CheckScript(valid) = %q, %v; want \"\", nil", warnings, err)
	}

	// Extension enabled in supportedExtensions is accepted.
	if _, err := session.CheckScript(context.Background(), "require \"fileinto\";\nfileinto \"Spam\";"); err != nil {
		t.Errorf("CheckScript(fileinto) = %v; want nil", err)
	}

	// Invalid syntax renders a quoted, response-splitting-safe *Error.
	_, err = session.CheckScript(context.Background(), "invalid_command;")
	var merr *managesieveserver.Error
	if !errors.As(err, &merr) {
		t.Fatalf("CheckScript(invalid) error type = %T, want *managesieveserver.Error", err)
	}
	if merr.Code != "" || !strings.HasPrefix(merr.Message, `"Script validation failed:`) {
		t.Errorf("CheckScript(invalid) = code %q message %q", merr.Code, merr.Message)
	}

	// Extension NOT in supportedExtensions is rejected.
	if _, err := session.CheckScript(context.Background(), "require \"vacation\";\nkeep;"); err == nil {
		t.Error("CheckScript(unsupported extension) = nil, want validation error")
	}
}

// TestHaveSpaceAdvisoryWithoutDB verifies HAVESPACE stays advisory when the
// DB layer is unavailable (unit-test construction): only the library-side
// size bound applies, so the session reports space optimistically.
func TestHaveSpaceAdvisoryWithoutDB(t *testing.T) {
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
			maxScriptSize: 1024,
		},
	}

	if err := session.HaveSpace(context.Background(), "myscript", 512); err != nil {
		t.Errorf("HaveSpace without DB = %v, want nil (advisory)", err)
	}
}
