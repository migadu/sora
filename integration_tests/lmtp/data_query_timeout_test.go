//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/lmtp"
)

// The database layer's own per-query timeout (query_timeout) firing while the DATA
// command is still within its cap is a slow database, not a shutdown: the message is
// deferred with the temporary 451 4.3.0 of any other failed save, never 421 4.2.1
// "service shutting down", which also closes the connection (#1932).
func TestLMTP_DataQueryTimeoutIsNotShutdown(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	rdb, err := resilient.NewResilientDatabase(context.Background(), &config.DatabaseConfig{
		QueryTimeout: "500ms",
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"},
			Port:  "5432",
			User:  "postgres",
			Name:  dbName,
		},
	}, false, true)
	if err != nil {
		t.Fatalf("database: %v", err)
	}
	t.Cleanup(rdb.Close)

	// The DATA cap stays far above the query timeout: only the query may time out.
	srv, account := common.SetupLMTPServerWithDatabase(t, rdb, lmtp.LMTPServerOptions{
		CommandTimeoutOverrides: map[string]time.Duration{"data": time.Minute},
	})
	defer srv.Close()

	// After RCPT, stall the INBOX lookup that stores the kept message: it reads
	// mailboxes, which this transaction holds locked until the test ends.
	stall := func() {
		tx, err := rdb.GetDatabase().GetWritePool().Begin(context.Background())
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		if _, err := tx.Exec(context.Background(), "LOCK TABLE mailboxes IN ACCESS EXCLUSIVE MODE"); err != nil {
			t.Fatalf("lock mailboxes: %v", err)
		}
	}

	marker := fmt.Sprintf("data-query-timeout-%d", time.Now().UnixNano())
	raw := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker +
		"\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n"
	response := deliverLMTPRawBeforeData(t, srv.Address, "sender@example.com", account.Email, raw, stall)
	if !strings.HasPrefix(response, "451 4.3.0") {
		t.Fatalf("DATA = %q, want 451 4.3.0 (a temporary failure, not service shutting down)", response)
	}
}
