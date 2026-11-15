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

// TestCheckScriptAcceptsRejectByDefault: scripts that require reject or
// ereject (RFC 5429) are stored under the default extension set. Delivery
// treats both as discard.
func TestCheckScriptAcceptsRejectByDefault(t *testing.T) {
	addr, err := server.NewAddress("test@example.com")
	if err != nil {
		t.Fatalf("NewAddress failed: %v", err)
	}
	session := &ManageSieveSession{
		Session:       server.Session{User: server.NewUser(addr, 123)},
		authenticated: true,
		ctx:           context.Background(),
		server: &ManageSieveServer{
			supportedExtensions: DefaultEnabledExtensions,
		},
	}
	for _, script := range []string{
		"require [\"fileinto\", \"reject\"];\nif header :contains \"subject\" \"ads\" { reject \"no\"; stop; }\nfileinto \"Junk\";",
		"require \"ereject\";\nereject \"no\";",
	} {
		if _, err := session.CheckScript(context.Background(), script); err != nil {
			t.Errorf("CheckScript(%q) = %v; want nil", script, err)
		}
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
		server:        &ManageSieveServer{},
	}

	if err := session.HaveSpace(context.Background(), "myscript", 512); err != nil {
		t.Errorf("HaveSpace without DB = %v, want nil (advisory)", err)
	}
}

// Scripts containing NUL bytes or invalid UTF-8 must be rejected at validation time by
// both CheckScript and PutScript as permanent uncoded NO validation errors rather than
// answering OK on CHECKSCRIPT and hitting PostgreSQL SQLSTATE 22021 (NO (TRYLATER)) on
// PUTSCRIPT.
func TestCheckAndPutScriptRefuseNULAndInvalidUTF8(t *testing.T) {
	addr, err := server.NewAddress("test@example.com")
	if err != nil {
		t.Fatalf("NewAddress failed: %v", err)
	}
	session := &ManageSieveSession{
		Session:       server.Session{User: server.NewUser(addr, 123)},
		authenticated: true,
		ctx:           context.Background(),
		server: &ManageSieveServer{
			supportedExtensions: DefaultEnabledExtensions,
		},
	}
	session.mutexHelper = server.NewMutexTimeoutHelper(&session.mutex, session.ctx, "MANAGESIEVE", func(string, ...any) {})

	for _, tc := range []struct {
		name   string
		script string
	}{
		{"NUL in hash comment", "# \x00\r\nkeep;\r\n"},
		{"NUL in bracket comment", "/* \x00 */\r\nkeep;\r\n"},
		{"NUL in quoted string", "require \"fileinto\";\r\nfileinto \"Spam\x00\";\r\n"},
		{"NUL in text block", "require \"vacation\";\r\nvacation text:\r\nout \x00\r\n.\r\n;\r\n"},
		{"invalid UTF-8 in hash comment", "# \xff\r\nkeep;\r\n"},
		{"invalid UTF-8 in quoted string", "require \"fileinto\";\r\nfileinto \"Spam\xff\";\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := session.CheckScript(context.Background(), tc.script)
			var merr *managesieveserver.Error
			if !errors.As(err, &merr) || merr.Code != "" || !strings.HasPrefix(merr.Message, `"Script validation failed:`) {
				t.Errorf("CheckScript(%s) = %v, want uncoded validation *managesieveserver.Error", tc.name, err)
			}

			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("PutScript(%s) bypassed validation and touched nil rdb (%v)", tc.name, r)
					}
				}()
				_, putErr := session.PutScript(context.Background(), "vacation", tc.script)
				var putMerr *managesieveserver.Error
				if !errors.As(putErr, &putMerr) || putMerr.Code != "" || !strings.HasPrefix(putMerr.Message, `"Script validation failed:`) {
					t.Errorf("PutScript(%s) = %v, want uncoded validation *managesieveserver.Error", tc.name, putErr)
				}
			}()
		})
	}
}
