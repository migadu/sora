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
