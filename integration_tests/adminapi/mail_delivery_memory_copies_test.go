//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/sieveengine"
)

// TestAdminAPI_DeliverMail_MemoryChargesTraceAndEditheaderCopies (#2116): on
// /admin/mail/deliver the Received/Delivered-To prepend copy and a Sieve
// editheader rewrite copy are charged to the delivery memory budget before they
// are allocated. A ~28 KiB raw message/rfc822 body charges 32 KiB as it is read,
// and about 28 KiB more for each of those copies.
func TestAdminAPI_DeliverMail_MemoryChargesTraceAndEditheaderCopies(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	editheader := append(append([]string{}, sieveengine.DefaultSieveExtensions...), "editheader")

	sizedBody := strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop\r\n", (28<<10)/64)
	deliver := func(t *testing.T, server *HTTPAPITestServer, email, name, body string, want int) {
		t.Helper()
		msg := fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", email, name, body)
		req, err := http.NewRequest("POST", server.URL+"/admin/mail/deliver?recipients="+email, bytes.NewBufferString(msg))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "message/rfc822")
		req.Header.Set("Authorization", "Bearer "+testAPIKey)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Errorf("%s: status %d (%s), want %d", name, resp.StatusCode, got, want)
		}
	}

	t.Run("trace header prepend copy", func(t *testing.T) {
		server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) { o.DeliveryMemoryLimit = 48 << 10 })
		defer server.Close()
		email := fmt.Sprintf("apimemtrace-%d@example.com", time.Now().UnixNano())
		createDeliveryAccount(t, server, email)
		deliver(t, server, email, "small", "hello\r\n", http.StatusOK)
		deliver(t, server, email, "body fits, the stamped copy does not", sizedBody, http.StatusServiceUnavailable)
		deliver(t, server, email, "small after the refusal", "hello\r\n", http.StatusOK)
	})

	t.Run("editheader rewrite copy", func(t *testing.T) {
		server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) {
			o.DeliveryMemoryLimit = 72 << 10
			o.SieveExtensions = editheader
		})
		defer server.Close()
		email := fmt.Sprintf("apimemedit-%d@example.com", time.Now().UnixNano())
		createDeliveryAccount(t, server, email)
		deliver(t, server, email, "no script: body and stamped copy fit", sizedBody, http.StatusOK)

		ctx := context.Background()
		accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
		if err != nil {
			t.Fatalf("lookup account: %v", err)
		}
		script := fmt.Sprintf("require \"editheader\";\r\n# %s\r\naddheader \"X-Edited\" \"yes\";\r\nkeep;\r\n", email)
		sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
		if err != nil {
			t.Fatalf("create sieve script: %v", err)
		}
		if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
			t.Fatalf("activate sieve script: %v", err)
		}
		deliver(t, server, email, "editheader copy does not fit", sizedBody, http.StatusServiceUnavailable)
		deliver(t, server, email, "small with editheader", "hello\r\n", http.StatusOK)
	})
}
