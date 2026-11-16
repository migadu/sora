//go:build integration

package imap_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// A correct password sent with AUTHENTICATE after the progressive auth delay
// has reached its default max_delay (30 s) still gets its tagged OK, as it does
// with LOGIN. The delay runs inside the login, and go-imap used to arm its 30 s
// response write deadline before the login: the OK could then not be written,
// and the client saw the connection close after a successful login.
func TestIMAP_AuthenticateOKAfterMaxAuthDelay(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const maxDelay = 30 * time.Second // config default for max_delay
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:             true,
		DelayStartThreshold: 1,
		InitialDelay:        maxDelay,
		MaxDelay:            maxDelay,
		DelayMultiplier:     2.0,
		MaxAttemptsPerIP:    10,
		IPWindowDuration:    5 * time.Minute,
	})
	defer srv.Close()

	// One failure from this address: the next login waits max_delay.
	conn, reader := dialAuthenticate(t, srv.Address)
	if _, err := fmt.Fprintf(conn, "A1 LOGIN %s wrongpassword\r\n", account.Email); err != nil {
		t.Fatal(err)
	}
	if line := readTagged(t, reader, "A1"); !strings.HasPrefix(line, "A1 NO") {
		t.Fatalf("LOGIN with a wrong password = %q, want NO", line)
	}
	conn.Close()

	conn, reader = dialAuthenticate(t, srv.Address)
	if err := conn.SetDeadline(time.Now().Add(maxDelay + 15*time.Second)); err != nil {
		t.Fatal(err)
	}
	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	start := time.Now()
	if _, err := fmt.Fprintf(conn, "A2 AUTHENTICATE PLAIN %s\r\n", creds); err != nil {
		t.Fatal(err)
	}
	line, err := reader.ReadString('\n')
	elapsed := time.Since(start)
	if err != nil || !strings.HasPrefix(line, "A2 OK ") {
		t.Fatalf("AUTHENTICATE after a %v auth delay = %q, %v (after %v); want a tagged OK", maxDelay, line, err, elapsed.Round(time.Millisecond))
	}
	if elapsed < maxDelay {
		t.Fatalf("AUTHENTICATE answered after %v, before the %v auth delay", elapsed, maxDelay)
	}

	if _, err := fmt.Fprint(conn, "A3 SELECT INBOX\r\n"); err != nil {
		t.Fatal(err)
	}
	if line := readTagged(t, reader, "A3"); !strings.HasPrefix(line, "A3 OK") {
		t.Fatalf("SELECT INBOX after AUTHENTICATE = %q, want OK", line)
	}
}
