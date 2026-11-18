package delivery

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// A spool disk that is full or read-only is the insufficient-storage condition LMTP
// answers with 452 4.3.1: for the recipient's own copy and for the copy staged under a
// shared mailbox's owner, the delivery error wraps ErrInsufficientStorage and the
// message names that condition, not the spool file (#1931).
func TestStagingFailureSpoolFullIsInsufficientStorage(t *testing.T) {
	tmp := "/var/spool/sora/42/0123abcd.0000000000000001.tmp"
	for _, tc := range []struct {
		errno syscall.Errno
		full  bool
	}{
		{syscall.ENOSPC, true},
		{syscall.EROFS, true},
		{syscall.EACCES, false},
	} {
		// Wrapped as stageFrom wraps it, and as resolveOwnedTarget wraps that.
		own := fmt.Errorf("failed to create file %s: %w", tmp, &fs.PathError{Op: "open", Path: tmp, Err: tc.errno})
		owner := fmt.Errorf("%w for the owner of mailbox '%s': %w", errStageOwnerCopy, "Shared/Team", own)
		for name, staged := range map[string]error{"own": own, "owner": owner} {
			t.Run(tc.errno.Error()+"/"+name, func(t *testing.T) {
				result := &DeliveryResult{}
				err := stagingFailure(result, "Failed to save message to disk", staged)
				if got := errors.Is(err, ErrInsufficientStorage); got != tc.full {
					t.Errorf("errors.Is(%v, ErrInsufficientStorage) = %v, want %v", err, got, tc.full)
				}
				if !errors.Is(err, tc.errno) {
					t.Errorf("error %v lost its cause %v", err, tc.errno)
				}
				if got := strings.HasPrefix(result.ErrorMessage, "Insufficient system storage"); got != tc.full {
					t.Errorf("ErrorMessage = %q, want insufficient storage %v", result.ErrorMessage, tc.full)
				}
				if !tc.full && result.ErrorMessage != "Failed to save message to disk: "+tc.errno.Error() {
					t.Errorf("ErrorMessage = %q, want the cause only", result.ErrorMessage)
				}
				if strings.Contains(result.ErrorMessage, "/var/spool") {
					t.Errorf("ErrorMessage exposes the spool path: %q", result.ErrorMessage)
				}
			})
		}
	}
}
