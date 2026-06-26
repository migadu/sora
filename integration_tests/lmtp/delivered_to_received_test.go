//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// setupLMTPForDelivery brings up an LMTP server backed by a local-disk uploader (so the
// stored message bytes can be read straight off disk) plus a fresh account. It returns
// the account, the LMTP listen address, and the uploader temp dir.
func setupLMTPForDelivery(t *testing.T, opts ...lmtpserver.LMTPServerOptions) (common.TestAccount, string, string) {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	tempDir := t.TempDir()
	uploaderInstance, err := uploader.NewWithS3Interface(
		tempDir, 10, 2, 3, time.Second, 0, "test-instance", rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create uploader: %v", err)
	}

	var serverOpts lmtpserver.LMTPServerOptions
	if len(opts) > 0 {
		serverOpts = opts[0]
	}

	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(
		context.Background(), "test-lmtp", "localhost", lmtpAddr,
		&storage.S3Storage{}, rdb, uploaderInstance, serverOpts,
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	t.Cleanup(func() { lmtpSrv.Close() })

	errChan := make(chan error, 1)
	go func() { lmtpSrv.Start(errChan) }()
	time.Sleep(200 * time.Millisecond)

	return account, lmtpAddr, tempDir
}

// deliverLMTPRaw runs one LMTP transaction and returns the per-recipient response that
// follows DATA (e.g. "250 ..." or "550 ..."). MAIL FROM / RCPT TO are expected to be
// accepted; the loop check happens during DATA.
func deliverLMTPRaw(t *testing.T, lmtpAddr, from, rcpt, message string) string {
	t.Helper()
	c, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP: %v", err)
	}
	defer c.Close()

	if err := c.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	if _, err := c.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO response: %v", err)
	}
	return runLMTPMailData(t, c, from, rcpt, message)
}

// deliverLMTPRawXCLIENT mimics a front proxy: it greets, sends an XCLIENT command to forward
// the real client's identity, handles the mandatory session reset (the server replies with a
// fresh 220 greeting), re-greets, then runs the transaction. It returns the per-recipient
// DATA response. xclientAttrs is the raw attribute string, e.g. "ADDR=203.0.113.9 HELO=...".
func deliverLMTPRawXCLIENT(t *testing.T, lmtpAddr, from, rcpt, message, xclientAttrs string) string {
	t.Helper()
	c, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP: %v", err)
	}
	defer c.Close()

	if err := c.SendCommand("LHLO proxy.internal"); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	if _, err := c.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO response: %v", err)
	}

	// XCLIENT: the server applies the forwarded attributes, resets the session, and replies
	// with a new 220 greeting (no separate 250 OK), exactly like the real LMTP proxy expects.
	if err := c.SendCommand("XCLIENT " + xclientAttrs); err != nil {
		t.Fatalf("XCLIENT: %v", err)
	}
	greeting, err := c.ReadResponse()
	if err != nil {
		t.Fatalf("XCLIENT response: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("expected 220 greeting after XCLIENT, got: %s", greeting)
	}

	// Client must re-issue LHLO after the reset (RFC/Postfix XCLIENT behavior).
	if err := c.SendCommand("LHLO proxy.internal"); err != nil {
		t.Fatalf("LHLO after XCLIENT: %v", err)
	}
	if _, err := c.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO-after-XCLIENT response: %v", err)
	}
	return runLMTPMailData(t, c, from, rcpt, message)
}

// runLMTPMailData runs the MAIL FROM / RCPT TO / DATA portion of a transaction on an already
// greeted connection and returns the per-recipient response that follows DATA.
func runLMTPMailData(t *testing.T, c *LMTPClient, from, rcpt, message string) string {
	t.Helper()
	if err := c.SendCommand(fmt.Sprintf("MAIL FROM:<%s>", from)); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if _, err := c.ReadResponse(); err != nil {
		t.Fatalf("MAIL FROM response: %v", err)
	}
	if err := c.SendCommand(fmt.Sprintf("RCPT TO:<%s>", rcpt)); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	rcptResp, err := c.ReadResponse()
	if err != nil {
		t.Fatalf("RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(rcptResp, "250") {
		t.Fatalf("expected 250 for RCPT TO, got: %s", rcptResp)
	}
	if err := c.SendCommand("DATA"); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if _, err := c.ReadResponse(); err != nil {
		t.Fatalf("DATA response: %v", err)
	}
	if err := c.SendCommand(message + "\r\n."); err != nil {
		t.Fatalf("send message: %v", err)
	}
	resp, err := c.ReadDataResponses(1)
	if err != nil {
		t.Fatalf("DATA per-recipient response: %v", err)
	}
	return resp[0]
}

// readStoredMessage returns the single stored message body written to the uploader temp
// dir (files are named by their 64-hex content hash under tempDir/<accountID>/).
func readStoredMessage(t *testing.T, tempDir string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && len(filepath.Base(path)) == 64 {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no stored message found under %s", tempDir)
	}
	b, err := os.ReadFile(found)
	if err != nil {
		t.Fatalf("read stored message: %v", err)
	}
	return string(b)
}

// TestLMTP_DeliveredToAndReceivedHeaders verifies that a delivered message is stamped
// with a Delivered-To header as the FIRST header, a Received: trace directly below it,
// and that the original headers are preserved.
func TestLMTP_DeliveredToAndReceivedHeaders(t *testing.T) {
	account, lmtpAddr, tempDir := setupLMTPForDelivery(t)

	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + account.Email,
		"Subject: Header Order Test",
		"Message-ID: <hdr-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
		"",
		"Body of the header order test.",
	}, "\r\n")

	resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg)
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250 delivery, got: %s", resp)
	}

	time.Sleep(500 * time.Millisecond)
	stored := readStoredMessage(t, tempDir)

	// 1. Delivered-To must be the very first header.
	wantFirst := "Delivered-To: " + account.Email + "\r\n"
	if !strings.HasPrefix(stored, wantFirst) {
		t.Errorf("Delivered-To must be the first header.\nwant prefix: %q\ngot head:\n%s", wantFirst, head(stored))
	}

	// 2. Received: must exist and come AFTER Delivered-To.
	dtIdx := strings.Index(stored, "Delivered-To: ")
	rcvIdx := strings.Index(stored, "Received: ")
	if rcvIdx < 0 {
		t.Fatalf("no Received: header in stored message:\n%s", head(stored))
	}
	if rcvIdx < dtIdx {
		t.Errorf("Received: (%d) must come after Delivered-To: (%d)\n%s", rcvIdx, dtIdx, head(stored))
	}

	// 3. Received: content for this LMTP delivery hop. Without any forwarded identity the
	// from-clause falls back to the connection's LHLO name.
	for _, want := range []string{
		"from test.example.com",
		"by localhost with LMTP",
		"for <" + account.Email + ">",
	} {
		if !strings.Contains(stored, want) {
			t.Errorf("Received: header missing %q\n%s", want, head(stored))
		}
	}

	// 4. Original headers and body preserved.
	for _, want := range []string{"Subject: Header Order Test", "From: sender@example.com", "Body of the header order test."} {
		if !strings.Contains(stored, want) {
			t.Errorf("original content missing %q", want)
		}
	}
}

// TestLMTP_ReceivedHeaderUsesForwardedClientIdentity verifies that when a trusted front
// proxy forwards the real client's identity via XCLIENT, the delivered message's Received:
// trace names the CLIENT (forwarded HELO + ADDR), not the proxy. This is the regression
// guard for the bug where XCLIENT attributes set on the pre-reset session were discarded:
// go-smtp resets the session after XCLIENT, so the attributes must be re-applied (from the
// data it persists on the Conn) onto the fresh session that actually delivers.
func TestLMTP_ReceivedHeaderUsesForwardedClientIdentity(t *testing.T) {
	// Trust loopback so the XCLIENT source-IP override is honored (both go-smtp's
	// XCLIENTTrustedNets and Sora's xclient trust derive from TrustedNetworks).
	account, lmtpAddr, tempDir := setupLMTPForDelivery(t, lmtpserver.LMTPServerOptions{
		TrustedNetworks: []string{"127.0.0.0/8", "::1/128"},
	})

	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + account.Email,
		"Subject: XCLIENT Trace Test",
		"Message-ID: <xcl-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
		"",
		"Body behind a proxy.",
	}, "\r\n")

	const clientIP = "203.0.113.9"
	const clientHELO = "upstream.example.net"
	resp := deliverLMTPRawXCLIENT(t, lmtpAddr, "sender@example.com", account.Email, msg,
		"ADDR="+clientIP+" HELO="+clientHELO+" PROTO=ESMTP")
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250 delivery, got: %s", resp)
	}

	time.Sleep(500 * time.Millisecond)
	stored := readStoredMessage(t, tempDir)

	// The Received: from-clause must reflect the forwarded client, not the (loopback) proxy.
	want := fmt.Sprintf("from %s ([%s])", clientHELO, clientIP)
	if !strings.Contains(stored, want) {
		t.Errorf("Received: must name the forwarded client %q\n%s", want, head(stored))
	}
	// And must NOT leak the proxy's LHLO name into the trace.
	if strings.Contains(stored, "from proxy.internal") {
		t.Errorf("Received: leaked the proxy LHLO name instead of the forwarded client\n%s", head(stored))
	}
}

// TestLMTP_RedirectLoopRejection verifies the Sora-specific loop detection: a message
// carrying our own X-Sora-Loop marker plus a matching Delivered-To is rejected, while a
// message with only a (foreign) Delivered-To — as a legitimate upstream forwarder would
// add — is accepted (no false positive).
func TestLMTP_RedirectLoopRejection(t *testing.T) {
	account, lmtpAddr, _ := setupLMTPForDelivery(t)

	// (a) Legitimately forwarded mail: a bare Delivered-To for this recipient, no
	// X-Sora-Loop. Must be accepted.
	upstream := strings.Join([]string{
		"Delivered-To: " + account.Email,
		"From: sender@example.com",
		"Subject: Legit Upstream Forward",
		"",
		"Forwarded body.",
	}, "\r\n")
	if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, upstream); !strings.HasPrefix(resp, "250") {
		t.Errorf("a bare upstream Delivered-To must be accepted (no false positive), got: %s", resp)
	}

	// (b) A Sora redirect loop: our X-Sora-Loop marker AND a matching Delivered-To.
	// Must be rejected with a 5.4.6 routing-loop error.
	looped := strings.Join([]string{
		"Delivered-To: " + account.Email,
		"X-Sora-Loop: 1",
		"From: sender@example.com",
		"Subject: Loop",
		"",
		"Looping body.",
	}, "\r\n")
	if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, looped); !strings.HasPrefix(resp, "550") {
		t.Errorf("X-Sora-Loop + matching Delivered-To must be rejected as a loop, got: %s", resp)
	}
}

// head returns the first part of a stored message for readable test failures.
func head(s string) string {
	if len(s) > 600 {
		return s[:600]
	}
	return s
}
