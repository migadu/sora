//go:build integration

package imap_test

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/internal/imaptest"
)

// Run the two original blackbox scenarios against fresh APPENDs so the stored
// search columns and the wire ENVELOPE are checked together, including group
// names after the first group and obsolete source-routed From addresses.
func TestIMAP_ImaptestAddressConformance(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	report, err := imaptest.Run(ctx, imaptest.Config{
		Addr:           server.Address,
		Username:       account.Email,
		Password:       account.Password,
		TLSMode:        "none",
		Clients:        4,
		Run:            `^imaptest/(search-addresses|fetch-envelope)$`,
		CommandTimeout: 10 * time.Second,
		CaseTimeout:    30 * time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("run address scenarios: %v", err)
	}
	for _, result := range report.Results {
		if result.Status != "pass" {
			t.Errorf("%s: %s: %s; cleanup=%v", result.Name, result.Status, result.Detail, result.CleanupErrors)
		}
	}
	if report.Passed != 2 || report.ExitCode() != 0 {
		t.Fatalf("address scenarios: passed=%d failed=%d skipped=%d errors=%d error=%s", report.Passed, report.Failed, report.Skipped, report.Errors, report.Error)
	}
}
