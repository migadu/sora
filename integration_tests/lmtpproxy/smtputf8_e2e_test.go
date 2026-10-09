//go:build integration

package lmtpproxy_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTPProxy_SMTPUTF8_EndToEnd drives the production path for the address that
// bounced: an MTA delivering RCPT TO:<user+josé@domain> into the real LMTP proxy
// (XCLIENT forwarding, as deployed), which relays to a real sora LMTP backend sharing
// an uploader with a real IMAP server. The message is then read back over IMAP from the
// mailbox the default Sieve script files it into (named after the detail, "josé"), and
// its trace headers are checked. Both transaction shapes are sent: the one the MTA
// actually used (no SMTPUTF8 parameter) and the RFC 6531 one (parameter and a
// non-ASCII sender).
func TestLMTPProxy_SMTPUTF8_EndToEnd(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// One uploader for both servers, synchronous so a delivered message is fetchable at
	// once (the same wiring as TestLMTP_PlusAddressingWithSharedUploader).
	sharedTempDir := t.TempDir()
	s3Storage := &storage.S3Storage{}
	sharedUploader, err := uploader.NewWithS3Interface(
		sharedTempDir, 10, 2, 3, time.Second, 0,
		"localhost", // must match the servers' hostname
		rdb, &common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("shared uploader: %v", err)
	}
	sharedUploader.EnableSyncUpload()
	if err := sharedUploader.Start(context.Background()); err != nil {
		t.Fatalf("start shared uploader: %v", err)
	}
	defer sharedUploader.Stop()

	// Real backend, trusting loopback so the proxy's XCLIENT is honoured, as in production.
	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(context.Background(), "test-lmtp", "localhost", lmtpAddr,
		s3Storage, rdb, sharedUploader,
		lmtpserver.LMTPServerOptions{TrustedNetworks: []string{"127.0.0.0/8", "::1/128"}})
	if err != nil {
		t.Fatalf("LMTP backend: %v", err)
	}
	defer lmtpSrv.Close()
	lmtpErrChan := make(chan error, 1)
	go func() { lmtpSrv.Start(lmtpErrChan) }()

	// Real IMAP server on the same database and uploader.
	imapAddr := common.GetRandomAddress(t)
	imapSrv, err := imapserver.New(context.Background(), "test-imap", "localhost", imapAddr,
		s3Storage, rdb, sharedUploader, nil, imapserver.IMAPServerOptions{InsecureAuth: true})
	if err != nil {
		t.Fatalf("IMAP server: %v", err)
	}
	defer imapSrv.Close()
	go func() {
		if err := imapSrv.Serve(imapAddr); err != nil {
			t.Logf("IMAP server: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	// Real proxy in front of the backend, forwarding the client identity via XCLIENT.
	proxyAddr, proxyWrapper := setupLMTPProxyWithXCLIENT(t, lmtpAddr)
	defer proxyWrapper.Close()

	local, domain, _ := strings.Cut(account.Email, "@")
	rcpt := local + "+josé@" + domain
	deliveries := []struct {
		name         string
		mailFromArgs string
		subject      string
	}{
		{"as the MTA sent it: no SMTPUTF8 parameter", "<sender@example.com>", "smtputf8 e2e without parameter"},
		{"RFC 6531 client: SMTPUTF8 parameter and non-ASCII sender", "<josé@sender.example> SMTPUTF8", "smtputf8 e2e with parameter"},
	}
	for _, d := range deliveries {
		message := strings.Join([]string{
			"From: sender@example.com",
			"To: " + rcpt,
			"Subject: " + d.subject,
			"Date: " + time.Now().Format(time.RFC1123Z),
			fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano()),
			"",
			"body",
		}, "\r\n")
		_, mailResp, rcptResp, dataResp := proxyTransactionMessage(t, proxyAddr, d.mailFromArgs, rcpt, message)
		requireProxyAccepted(t, mailResp, rcptResp, dataResp)
		t.Logf("%s: MAIL %q RCPT %q DATA %q", d.name, mailResp, rcptResp, dataResp)
	}

	// Read both back over IMAP from the mailbox the default Sieve script created for the
	// detail; selecting it exercises the non-ASCII mailbox name on the IMAP side too.
	c, err := imapclient.DialInsecure(imapAddr, nil)
	if err != nil {
		t.Fatalf("dial IMAP: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("IMAP login: %v", err)
	}
	selected, err := c.Select("josé", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT josé (the mailbox the default Sieve script files +josé into): %v", err)
	}
	if selected.NumMessages != uint32(len(deliveries)) {
		t.Fatalf("mailbox josé has %d messages, want %d", selected.NumMessages, len(deliveries))
	}

	var all imap.SeqSet
	all.AddRange(1, 0)
	fetchCmd := c.Fetch(all, &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{Part: []int{}}}, // BODY[]
	})
	bodies := map[string]string{} // subject -> raw message
	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if bodyItem, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := new(bytes.Buffer)
				if _, err := io.Copy(buf, bodyItem.Literal); err != nil {
					t.Fatalf("read BODY[]: %v", err)
				}
				raw := buf.String()
				for _, d := range deliveries {
					if strings.Contains(raw, "Subject: "+d.subject+"\r\n") {
						bodies[d.subject] = raw
					}
				}
			}
		}
	}
	if err := fetchCmd.Close(); err != nil {
		t.Fatalf("FETCH: %v", err)
	}

	for _, d := range deliveries {
		raw, ok := bodies[d.subject]
		if !ok {
			t.Fatalf("%s: message not fetched over IMAP (got subjects %v)", d.name, keys(bodies))
		}
		for _, want := range []string{
			"Delivered-To: " + account.Email + "\r\n", // the account's primary address, not the +detail form
			"for <" + account.Email + ">",
			"with UTF8LMTP", // RFC 6531 §3.7.3: an internationalized transaction, with or without the parameter
		} {
			if !strings.Contains(raw, want) {
				t.Errorf("%s: fetched message lacks %q\n%s", d.name, want, raw[:min(len(raw), 600)])
			}
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
