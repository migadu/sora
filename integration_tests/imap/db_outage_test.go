//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
)

// imapLoginReply sends one LOGIN on a fresh connection and returns the tagged reply.
func imapLoginReply(t *testing.T, address, username, password string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	fmt.Fprintf(conn, "a1 LOGIN %q %q\r\n", username, password)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("LOGIN reply: %v", err)
		}
		if strings.HasPrefix(line, "a1 ") {
			return strings.TrimSpace(line)
		}
	}
}

// TestIMAPLoginDuringDatabaseOutage: a login the database cannot answer is a temporary
// failure, NO [UNAVAILABLE] (RFC 5530 section 3), not a wrong password, and it is not
// counted by the auth rate limiter, so the user logs in once the database is back.
func TestIMAPLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := serverImap.New(context.Background(), "test-db-outage", "localhost", address,
		&storage.S3Storage{}, rdb, nil, nil,
		serverImap.IMAPServerOptions{
			InsecureAuth:  true,
			AuthRateLimit: common.DBOutageAuthRateLimit(),
		})
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}
	go func() { _ = srv.Serve(address) }()
	defer srv.Close()
	time.Sleep(100 * time.Millisecond)

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := imapLoginReply(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("LOGIN %d during a database outage: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	outage.End()

	if reply := imapLoginReply(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Errorf("LOGIN after the outage: %q, want a1 OK (the outage was counted as failed logins)", reply)
	}
}

// TestIMAPCachedLoginDuringDatabaseOutageIsUnavailable: a login answered from the
// lookup cache during a database outage passes the password check and then fails to
// ensure the default mailboxes, on a pooled connection the outage closed. A subsystem
// is down: the reply is NO [UNAVAILABLE] (RFC 5530 section 3), not
// NO [SERVERBUG] ...: conn closed.
func TestIMAPCachedLoginDuringDatabaseOutageIsUnavailable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := startIMAPWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	if reply := imapLoginReply(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Fatalf("LOGIN before the outage: %q, want a1 OK", reply)
	}

	logs := common.CaptureLogs(t)
	outage.Begin()
	defer outage.End()
	reply := imapLoginReply(t, address, account.Email, account.Password)
	// The session went on to the default mailboxes, so the password check passed: the
	// lookup cache answered it, the database could not have. The login did not
	// succeed, so there is no "authentication successful" line to say so.
	logs.WaitForLine(t, "failed to create default mailboxes")
	if !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
		t.Errorf("cached LOGIN during a database outage: %q, want a1 NO [UNAVAILABLE] ...", reply)
	}
}

// TestIMAPDatabaseOutageDropsCachedLogin: a login in the backend's lookup cache keeps
// signing in during a database outage while it is younger than
// positive_revalidation_window (30s by default). A password that misses it goes to the
// database, which gives no verdict, so the guess is not counted. The cached login must
// be dropped then, or every later guess is checked against the cached password,
// uncounted, until the entry is older than the window. Once the database is back, the
// user logs in: the guesses were not counted.
func TestIMAPDatabaseOutageDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := startIMAPWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	if reply := imapLoginReply(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Fatalf("LOGIN before the outage: %q, want a1 OK", reply)
	}

	logs := common.CaptureLogs(t)
	outage.Begin()
	// Before any guess the cached login still signs in. The session it opens needs the
	// database, so the reply is not the point: the session going on to the default
	// mailboxes says the lookup cache passed the password, as the database could not.
	imapLoginReply(t, address, account.Email, account.Password)
	logs.WaitForLine(t, "failed to create default mailboxes")

	for i := 1; i <= 3; i++ {
		if reply := imapLoginReply(t, address, account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("LOGIN with guess %d during the outage: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	if reply := imapLoginReply(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
		t.Errorf("LOGIN with the cached password after the guesses: %q, want a1 NO [UNAVAILABLE] (the uncounted guesses were checked against the cached login)", reply)
	}
	outage.End()

	if reply := imapLoginReply(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Errorf("LOGIN after the outage: %q, want a1 OK (the guesses were counted as failed logins)", reply)
	}
}
