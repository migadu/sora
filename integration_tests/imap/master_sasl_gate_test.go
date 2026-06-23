//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// setupIMAPServerWithMasterSASLGate creates a backend IMAP server configured with
// master SASL credentials and a master_sasl_allowed_networks gate. TrustedNetworks
// always trusts localhost so the IMAP ID forwarding path is honored — this lets the
// "not forwardable" test forge an x-originating-ip and prove the gate ignores it.
func setupIMAPServerWithMasterSASLGate(t *testing.T, allowedNetworks []string) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-gate-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(), tempDir, 10, 1, 3, time.Second, 0,
		"test-instance", rdb, &storage.S3Storage{}, nil, errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil,
		imap.IMAPServerOptions{
			InsecureAuth:              true,
			Config:                    &config.Config{},
			TrustedNetworks:           []string{"127.0.0.0/8", "::1/128"}, // honor ID forwarding from localhost
			MasterUsername:            []byte(masterUsername),
			MasterPassword:            []byte(masterPassword),
			MasterSASLUsername:        []byte(masterSASLUsername),
			MasterSASLPassword:        []byte(masterSASLPassword),
			MasterSASLAllowedNetworks: allowedNetworks,
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
		os.RemoveAll(tempDir)
	})

	return &common.TestServer{Address: address, Server: server, ResilientDB: rdb}, account
}

// TestIMAP_MasterSASLGate_BlocksOffNetwork proves that when master_sasl_allowed_networks
// is set to a range that excludes the connecting socket, master SASL impersonation is
// refused — while the support-facing master *username* path and regular auth still work
// (the gate is scoped to master SASL only).
func TestIMAP_MasterSASLGate_BlocksOffNetwork(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Loopback (127.0.0.1) is NOT inside this range.
	server, account := setupIMAPServerWithMasterSASLGate(t, []string{"10.99.0.0/16"})

	t.Run("master SASL denied from off-network peer", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Logout()

		saslClient := &plainSASLClient{
			identity: account.Email,
			username: masterSASLUsername,
			password: masterSASLPassword,
		}
		if err := c.Authenticate(saslClient); err == nil {
			t.Fatal("expected master SASL to be denied from off-network peer, but it succeeded")
		} else {
			t.Logf("✓ master SASL correctly denied off-network: %v", err)
		}
	})

	t.Run("master username (support path) still works", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Logout()

		// Support logs in with user@domain@MASTER_USERNAME — not gated by network.
		if err := c.Login(account.Email+"@"+masterUsername, masterPassword).Wait(); err != nil {
			t.Fatalf("master username login should not be gated, but failed: %v", err)
		}
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			t.Fatalf("select after master username login: %v", err)
		}
		t.Log("✓ master username path unaffected by master_sasl_allowed_networks")
	})

	t.Run("regular auth still works", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Logout()
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("regular login: %v", err)
		}
		t.Log("✓ regular auth unaffected")
	})
}

// TestIMAP_MasterSASLGate_AllowsOnNetwork is the control: when the gate includes the
// connecting socket's network, master SASL impersonation succeeds as before.
func TestIMAP_MasterSASLGate_AllowsOnNetwork(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := setupIMAPServerWithMasterSASLGate(t, []string{"127.0.0.0/8", "::1/128"})

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Logout()

	saslClient := &plainSASLClient{
		identity: account.Email,
		username: masterSASLUsername,
		password: masterSASLPassword,
	}
	if err := c.Authenticate(saslClient); err != nil {
		t.Fatalf("master SASL should succeed from allowed network: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("select after master SASL: %v", err)
	}
	t.Log("✓ master SASL succeeds from allow-listed network")
}

// TestIMAP_MasterSASLGate_NotForwardable proves the gate is anchored to the real TCP
// peer and cannot be bypassed by forging an allow-listed client IP via the IMAP ID
// command. The forged x-originating-ip lands inside the allowed range, yet the gate —
// reading the true socket peer (127.0.0.1) — still refuses.
func TestIMAP_MasterSASLGate_NotForwardable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Allowed range matches the forged originating IP below, but NOT the loopback socket.
	server, account := setupIMAPServerWithMasterSASLGate(t, []string{"10.99.0.0/16"})

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(conn)
	readUntilTag := func(tag string) string {
		var last string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("read (waiting for %s): %v", tag, err)
			}
			last = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(last, tag+" ") {
				return last
			}
		}
	}

	// Greeting
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Forge a client IP inside the allowed master-SASL range via the ID command.
	// TrustedNetworks trusts localhost, so the backend honors this forwarding and
	// rewrites the session's RemoteIP to 10.99.0.5 — the spoof a gate keyed on the
	// session IP would fall for.
	fmt.Fprintf(conn, "a1 ID (\"x-originating-ip\" \"10.99.0.5\" \"x-proxy-ttl\" \"5\")\r\n")
	if resp := readUntilTag("a1"); !strings.HasPrefix(resp, "a1 OK") {
		t.Fatalf("ID command not accepted: %q", resp)
	}

	// Now attempt master SASL impersonation with a valid secret.
	authString := account.Email + "\x00" + masterSASLUsername + "\x00" + masterSASLPassword
	ir := base64.StdEncoding.EncodeToString([]byte(authString))
	fmt.Fprintf(conn, "a2 AUTHENTICATE PLAIN %s\r\n", ir)

	resp := readUntilTag("a2")
	if !strings.HasPrefix(resp, "a2 NO") {
		t.Fatalf("expected master SASL to be denied despite forged originating IP, got: %q", resp)
	}
	t.Logf("✓ gate anchored to socket peer; forged x-originating-ip ignored: %q", resp)
}
