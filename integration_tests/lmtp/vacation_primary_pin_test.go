//go:build integration

package lmtp_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message/mail"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
)

func setupSplitPrimaryAndLaggingReplica(t *testing.T) (*resilient.ResilientDatabase, func(createSchemaTables func(ctx context.Context, schema string))) {
	t.Helper()
	ctx := context.Background()
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_mail_db"
	}
	// Ensure migrations are up to date first via SetupTestDatabase.
	_ = common.SetupTestDatabase(t)

	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"},
			Port:  "5432",
			User:  "postgres",
			Name:  name,
		},
	}, false, true)
	if err != nil {
		t.Fatalf("NewResilientDatabase: %v", err)
	}
	t.Cleanup(rdb.Close)

	installReplica := func(createSchemaTables func(ctx context.Context, schema string)) {
		database := rdb.GetDatabase()
		schema := pgx.Identifier{fmt.Sprintf("lmtp_replica_%d", time.Now().UnixNano())}.Sanitize()
		if _, err := database.WritePool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
			t.Fatalf("create replica schema: %v", err)
		}
		t.Cleanup(func() { _, _ = database.WritePool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") })

		createSchemaTables(ctx, schema)

		replicaConfig := database.WritePool.Config().Copy()
		replicaConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, "SET search_path TO "+schema+", public")
			return err
		}
		replica, err := pgxpool.NewWithConfig(ctx, replicaConfig)
		if err != nil {
			t.Fatalf("NewWithConfig: %v", err)
		}
		t.Cleanup(replica.Close)
		originalRead := database.ReadPool
		if originalRead != nil && originalRead != database.WritePool {
			t.Cleanup(originalRead.Close)
		}
		database.ReadPool = replica
	}
	return rdb, installReplica
}

// TestLMTP_VacationHonorsPrimaryPinOnLaggingReplica verifies that after RCPT TO
// pins the LMTP session to the primary (s.useMasterDB = true), handleVacationResponse
// checks recipient/sender credential ownership on the primary rather than a lagging
// read replica — preventing silent vacation suppression (after VacationOracle already
// wrote the :days claim on the primary) and stale :from ownership checks.
func TestLMTP_VacationHonorsPrimaryPinOnLaggingReplica(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	rdb, installReplica := setupSplitPrimaryAndLaggingReplica(t)
	stamp := time.Now().UnixNano()
	primary := fmt.Sprintf("vac-primary-%d@example.com", stamp)
	alias := fmt.Sprintf("vac-alias-%d@example.com", stamp)

	accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     primary,
		Password:  "password-123456",
		HashType:  "bcrypt",
		IsPrimary: true,
	})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := rdb.AddCredentialWithRetry(ctx, db.AddCredentialRequest{
		AccountID:   accountID,
		NewEmail:    alias,
		NewPassword: "password-654321",
		NewHashType: "bcrypt",
	}); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	setActiveSieveScript(t, rdb, accountID, strings.Join([]string{
		`require ["vacation"];`,
		`vacation :days 1 :from "` + alias + `" "Away on alias.";`,
	}, "\r\n")+"\r\n")

	// Simulate replica lag: the read pool does not yet have the new alias row.
	installReplica(func(ctx context.Context, schema string) {
		if _, err := rdb.GetDatabase().WritePool.Exec(ctx,
			"CREATE TABLE "+schema+".credentials AS SELECT * FROM public.credentials WHERE address <> $1",
			alias); err != nil {
			t.Fatalf("shadow credentials: %v", err)
		}
	})

	rq := &captureRelayQueue{}
	lmtpAddr := startTestLMTPServerWithRedirect(t, rdb, rq, 10, time.Hour)

	sender := fmt.Sprintf("sender-%d@example.org", stamp)
	msg := strings.Join([]string{
		"From: " + sender,
		"To: " + alias,
		"Subject: Urgent alias question",
		fmt.Sprintf("Message-ID: <vac-%d@example.org>", stamp),
		"",
		"Hello!",
	}, "\r\n")
	if resp := deliverLMTPRaw(t, lmtpAddr, sender, alias, msg); !strings.HasPrefix(resp, "250") {
		t.Fatalf("delivery not accepted: %s", resp)
	}

	var replies []relayItem
	for _, it := range rq.items() {
		if it.msgType == "vacation" {
			replies = append(replies, it)
		}
	}
	if len(replies) != 1 {
		t.Fatalf("vacation replies = %d, want 1 (lagging read replica suppressed reply after primary claimed :days)", len(replies))
	}

	entity, err := mail.CreateReader(bytes.NewReader(replies[0].body))
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	fromList, err := entity.Header.AddressList("From")
	if err != nil || len(fromList) != 1 || !strings.EqualFold(fromList[0].Address, alias) {
		t.Errorf("vacation reply From = %v (err=%v), want %s (lagging replica rejected owned :from alias)", fromList, err, alias)
	}
}

// TestLMTP_RedirectRateLimitHonorsPrimaryPinOnLaggingReplica verifies that Sieve
// evaluation in a primary-pinned LMTP session checks redirect_log on the primary
// rather than an empty/lagging read replica, so redirect_rate_limit cannot be
// bypassed while replica replication lags.
func TestLMTP_RedirectRateLimitHonorsPrimaryPinOnLaggingReplica(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	rdb, installReplica := setupSplitPrimaryAndLaggingReplica(t)
	stamp := time.Now().UnixNano()
	primary := fmt.Sprintf("redir-primary-%d@example.com", stamp)

	accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     primary,
		Password:  "password-123456",
		HashType:  "bcrypt",
		IsPrimary: true,
	})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	const target = "forwarded@example.net"
	setActiveSieveScript(t, rdb, accountID, `redirect "`+target+`";`+"\r\n")

	// Simulate replica lag on redirect_log: the read pool never sees newly inserted redirects.
	installReplica(func(ctx context.Context, schema string) {
		if _, err := rdb.GetDatabase().WritePool.Exec(ctx,
			"CREATE TABLE "+schema+".redirect_log AS SELECT * FROM public.redirect_log WHERE false"); err != nil {
			t.Fatalf("shadow redirect_log: %v", err)
		}
	})

	rq := &captureRelayQueue{}
	// Allow at most 1 redirect per hour.
	lmtpAddr := startTestLMTPServerWithRedirect(t, rdb, rq, 1, time.Hour)

	for i := 1; i <= 2; i++ {
		sender := fmt.Sprintf("sender-%d-%d@example.org", i, stamp)
		msg := strings.Join([]string{
			"From: " + sender,
			"To: " + primary,
			"Subject: Forward test",
			fmt.Sprintf("Message-ID: <redir-%d-%d@example.org>", i, stamp),
			"",
			"Hello!",
		}, "\r\n")
		if resp := deliverLMTPRaw(t, lmtpAddr, sender, primary, msg); !strings.HasPrefix(resp, "250") {
			t.Fatalf("delivery %d not accepted: %s", i, resp)
		}
	}

	var redirects int
	for _, it := range rq.items() {
		if it.msgType == "redirect" {
			redirects++
		}
	}
	if redirects != 1 {
		t.Errorf("redirects queued = %d, want 1 (redirect_rate_limit=1 bypassed via lagging read replica)", redirects)
	}
}
