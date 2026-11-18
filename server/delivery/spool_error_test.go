package delivery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
)

// spoolTestAccountID is the recipient whose staging directory the tests break.
const spoolTestAccountID = 42

// The Admin API returns DeliveryResult.ErrorMessage to its client. A body that could
// not be written to the local spool must be reported without the spool's file names:
// the error the uploader returns names them, and it is for the server log (#1931).
func TestDeliverMessageSpoolFailureHidesPath(t *testing.T) {
	t.Run("store", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes into a read-only directory")
		}
		// A spool the account's staging directory cannot be created in: StoreLocally
		// fails before any database access.
		testDeliverMessageSpoolFailureHidesPath(t, func(spool string) {
			if err := os.Chmod(spool, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(spool, 0o755) })
		})
	})
	t.Run("stat", func(t *testing.T) {
		// A regular file where the account's staging directory belongs: looking for an
		// already staged body fails.
		testDeliverMessageSpoolFailureHidesPath(t, func(spool string) {
			if err := os.WriteFile(filepath.Join(spool, fmt.Sprint(spoolTestAccountID)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		})
	})
}

func testDeliverMessageSpoolFailureHidesPath(t *testing.T, breakSpool func(spool string)) {
	t.Helper()
	spool := t.TempDir()
	up, err := uploader.NewWithS3Interface(spool, 10, 1, 3, time.Second, 0, "delivery-test", nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	breakSpool(spool)

	addr, err := server.NewAddress("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	dctx := &DeliveryContext{
		Ctx:          context.Background(),
		Uploader:     up,
		Hostname:     "mx.example.com",
		MetricsLabel: "http_delivery",
		Logger:       nopDeliveryLogger{},
	}
	msg := []byte("From: bob@example.com\r\nTo: alice@example.com\r\nSubject: hi\r\n\r\nhello\r\n")
	result, err := dctx.DeliverMessage(RecipientInfo{
		AccountID:     spoolTestAccountID,
		Address:       &addr,
		ToAddress:     &addr,
		TargetMailbox: "INBOX", // no Sieve, so no database
	}, msg)
	if err == nil {
		t.Fatal("DeliverMessage succeeded with an unwritable spool")
	}
	if result.ErrorMessage == "" {
		t.Fatalf("no ErrorMessage for staging failure %v", err)
	}
	if strings.Contains(result.ErrorMessage, spool) {
		t.Fatalf("ErrorMessage exposes the spool path: %q", result.ErrorMessage)
	}
}
