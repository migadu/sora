//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

const icewarpCap = "X-ICEWARP-SERVER"

// setupIMAPServerWithAdditionalCaps creates an IMAP server that advertises the
// given extra capability tokens verbatim (config: additional_caps).
func setupIMAPServerWithAdditionalCaps(t *testing.T, additionalCaps []string) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,
		10,
		1,
		3,
		time.Second,
		0,
		"test-instance",
		rdb,
		&storage.S3Storage{},
		nil,
		errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := imapserver.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil,
		imapserver.IMAPServerOptions{
			InsecureAuth:   true,
			AdditionalCaps: additionalCaps,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	t.Cleanup(func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
		os.RemoveAll(tempDir)
	})

	return &common.TestServer{
		Address:     address,
		Server:      server,
		ResilientDB: rdb,
	}, account
}

// readGreeting dials the server with a raw TCP connection and returns the
// untagged greeting line, which carries the pre-auth [CAPABILITY ...] code.
func readGreeting(t *testing.T, address string) string {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	line, _, err := bufio.NewReader(conn).ReadLine()
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	return string(line)
}

// TestIMAP_AdditionalCaps verifies a configured additional capability token is
// advertised verbatim at every point a client reads capabilities: the pre-auth
// greeting, the standard go-imap client capability set (post-login), and the
// explicit CAPABILITY command.
func TestIMAP_AdditionalCaps(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupIMAPServerWithAdditionalCaps(t, []string{icewarpCap})
	defer server.Close()

	// 1. Pre-auth greeting must carry the token (this is the earliest point, and
	// where the standard backend-gated capabilities are NOT yet emitted).
	greeting := readGreeting(t, server.Address)
	t.Logf("Greeting: %s", greeting)
	if !strings.Contains(greeting, icewarpCap) {
		t.Errorf("greeting [CAPABILITY] missing %q: %s", icewarpCap, greeting)
	}

	// 2. go-imap client capability set (captured from greeting + post-login).
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if !c.Caps().Has(imap.Cap(icewarpCap)) {
		t.Errorf("pre-login client caps missing %q: %v", icewarpCap, capList(c.Caps()))
	}

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// 3. Explicit CAPABILITY command after login.
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command failed: %v", err)
	}
	if !caps.Has(imap.Cap(icewarpCap)) {
		t.Errorf("post-login CAPABILITY missing %q: %v", icewarpCap, capList(caps))
	}

	// Sanity: a standard capability is still present (token augments, not replaces).
	if !caps.Has(imap.CapIMAP4rev1) {
		t.Errorf("standard IMAP4rev1 capability missing after adding token: %v", capList(caps))
	}

	t.Logf("SUCCESS: %q advertised in greeting, pre-login caps, and post-login CAPABILITY", icewarpCap)
}

// TestIMAP_AdditionalCaps_Absent verifies the token is NOT advertised when
// additional_caps is unset (negative control).
func TestIMAP_AdditionalCaps_Absent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupIMAPServerWithAdditionalCaps(t, nil)
	defer server.Close()

	greeting := readGreeting(t, server.Address)
	if strings.Contains(greeting, icewarpCap) {
		t.Errorf("greeting unexpectedly advertised %q: %s", icewarpCap, greeting)
	}

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command failed: %v", err)
	}
	if caps.Has(imap.Cap(icewarpCap)) {
		t.Errorf("CAPABILITY unexpectedly advertised %q: %v", icewarpCap, capList(caps))
	}
}

func capList(caps imap.CapSet) []string {
	var l []string
	for c := range caps {
		l = append(l, string(c))
	}
	return l
}
