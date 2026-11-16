//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTPProxyESMTPParameters checks that the LMTP proxy answers MAIL and RCPT
// parameters as the backend does: it takes SIZE, BODY=7BIT/8BITMIME and SMTPUTF8,
// and refuses the others (the DSN parameters among them) with 555 5.5.4.
func TestLMTPProxyESMTPParameters(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	rdb := common.SetupTestDatabase(t)

	// Create test account
	testAccount := common.CreateTestAccount(t, rdb)
	t.Logf("Created test account: %s", testAccount.Email)

	// Initialize S3 storage (empty struct for testing)
	s3 := &storage.S3Storage{}

	// Create upload worker for backend server
	tempDir := t.TempDir()
	uploadWorker, err := uploader.New(
		ctx,
		tempDir,
		10,            // batch size
		2,             // concurrency
		3,             // max attempts
		5*time.Second, // retry interval
		0,             // maxStagingSize
		"test-backend",
		rdb,
		s3,
		nil, // cache
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}
	t.Cleanup(func() {
		uploadWorker.Stop()
	})

	// Start backend LMTP server
	backendAddr := "127.0.0.1:12425"
	backendServer, err := lmtp.New(ctx, "test-backend", "localhost", backendAddr, s3, rdb, uploadWorker, lmtp.LMTPServerOptions{
		Debug: true,
	})
	if err != nil {
		t.Fatalf("Failed to create backend LMTP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		backendServer.Start(errChan)
	}()
	t.Cleanup(func() {
		// Backend has no Shutdown method, just let it close when test ends
	})

	// Wait for backend to start
	time.Sleep(200 * time.Millisecond)

	// Start LMTP proxy
	proxyAddr := "127.0.0.1:12426"
	proxyOpts := lmtpproxy.ServerOptions{
		Name:           "test-proxy",
		Addr:           proxyAddr,
		RemoteAddrs:    []string{backendAddr},
		TrustedProxies: []string{"127.0.0.1/32"}, // Allow local connections
		MaxMessageSize: 52428800,                 // advertised as SIZE, as in production
		Debug:          true,
	}

	proxy, err := lmtpproxy.New(ctx, rdb, "localhost", proxyOpts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil {
			t.Logf("LMTP proxy error: %v", err)
		}
	}()
	t.Cleanup(func() {
		proxy.Stop()
	})

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// The proxy answers every parameter as the backend does (#1562): 555 5.5.4 for one
	// it does not implement, the DSN parameters among them, since neither announces DSN.
	// RFC 5321 section 4.1.1.11: "If the server SMTP does not recognize or cannot
	// implement one or more of the parameters associated with a particular MAIL FROM or
	// RCPT TO command, it will return code 555."
	testCases := []struct {
		name        string
		mailCommand string // "" for a plain MAIL FROM
		rcptCommand string // "" to check the reply to the MAIL
		want        string // prefix of the reply to the last command sent
	}{
		{
			name:        "RCPT with NOTIFY=NEVER",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> NOTIFY=NEVER", testAccount.Email),
			want:        "555 5.5.4 ",
		},
		{
			name:        "RCPT with NOTIFY=SUCCESS,FAILURE",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> NOTIFY=SUCCESS,FAILURE", testAccount.Email),
			want:        "555 5.5.4 ",
		},
		{
			name:        "RCPT with ORCPT parameter",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> ORCPT=rfc822;%s", testAccount.Email, testAccount.Email),
			want:        "555 5.5.4 ",
		},
		{
			name:        "RCPT with multiple DSN parameters",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> NOTIFY=NEVER ORCPT=rfc822;%s", testAccount.Email, testAccount.Email),
			want:        "555 5.5.4 ",
		},
		{
			name:        "RCPT with space after TO:",
			rcptCommand: fmt.Sprintf("RCPT TO: <%s> NOTIFY=NEVER", testAccount.Email),
			want:        "555 5.5.4 ",
		},
		{
			name:        "RCPT with an unknown parameter",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> FOO=1", testAccount.Email),
			want:        "555 5.5.4 ",
		},
		{
			name:        "Plain RCPT without parameters",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s>", testAccount.Email),
			want:        "250",
		},
		{
			name:        "MAIL with RET and ENVID",
			mailCommand: "MAIL FROM:<sender@example.com> RET=HDRS ENVID=QQ314159",
			want:        "555 5.5.4 ",
		},
		{
			name:        "MAIL with an unknown parameter",
			mailCommand: "MAIL FROM:<sender@example.com> FOO=1",
			want:        "555 5.5.4 ",
		},
		{
			name:        "MAIL with BODY=BINARYMIME",
			mailCommand: "MAIL FROM:<sender@example.com> BODY=BINARYMIME",
			want:        "555 5.5.4 ",
		},
		{
			name:        "MAIL with an unknown BODY value",
			mailCommand: "MAIL FROM:<sender@example.com> BODY=BINARY",
			want:        "501 5.5.4 ",
		},
		{
			name:        "MAIL with SIZE, BODY=8BITMIME and SMTPUTF8",
			mailCommand: "MAIL FROM:<sender@example.com> SIZE=100 BODY=8BITMIME SMTPUTF8",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s>", testAccount.Email),
			want:        "250",
		},
	}

	for _, target := range []struct{ name, addr string }{{"backend", backendAddr}, {"proxy", proxyAddr}} {
		for _, tc := range testCases {
			t.Run(target.name+"/"+tc.name, func(t *testing.T) {
				conn, err := net.DialTimeout("tcp", target.addr, 5*time.Second)
				if err != nil {
					t.Fatalf("Failed to connect to the %s: %v", target.name, err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))

				reader := bufio.NewReader(conn)
				send := func(line string) string {
					t.Helper()
					if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
						t.Fatalf("Failed to send %q: %v", line, err)
					}
					for {
						l, err := reader.ReadString('\n')
						if err != nil {
							t.Fatalf("Failed to read the reply to %q: %v", line, err)
						}
						reply := strings.TrimRight(l, "\r\n")
						if len(reply) < 4 || reply[3] != '-' {
							return reply
						}
						// DSN is not announced, so the MTA keeps the DSN duties (RFC 3461
						// §5.2.2).
						if fields := strings.Fields(reply[4:]); len(fields) > 0 && strings.EqualFold(fields[0], "DSN") {
							t.Errorf("LHLO announces DSN: %q", reply)
						}
					}
				}

				if greeting, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "220") {
					t.Fatalf("Unexpected greeting: %q, %v", greeting, err)
				}
				if reply := send("LHLO localhost"); !strings.HasPrefix(reply, "250 ") {
					t.Fatalf("LHLO: %q", reply)
				}

				mail := tc.mailCommand
				if mail == "" {
					mail = "MAIL FROM:<sender@example.com>"
				}
				reply := send(mail)
				if tc.rcptCommand != "" {
					if !strings.HasPrefix(reply, "250") {
						t.Fatalf("%s: %q, want 250", mail, reply)
					}
					reply = send(tc.rcptCommand)
				}
				if !strings.HasPrefix(reply, tc.want) {
					t.Errorf("%s answered %q, want %q", target.name, reply, tc.want)
				}
				send("QUIT")
			})
		}
	}
}

// TestLMTPProxyFullDeliveryWithESMTP tests a complete message delivery through the
// proxy with the MAIL parameters it takes, and that a recipient refused for a
// parameter it does not take (555) leaves the transaction open.
func TestLMTPProxyFullDeliveryWithESMTP(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	rdb := common.SetupTestDatabase(t)

	// Create test account
	testAccount := common.CreateTestAccount(t, rdb)
	t.Logf("Created test account: %s", testAccount.Email)

	// Initialize S3 storage (empty struct for testing)
	s3 := &storage.S3Storage{}

	// Create upload worker for backend server
	tempDir := t.TempDir()
	uploadWorker, err := uploader.New(
		ctx,
		tempDir,
		10,            // batch size
		2,             // concurrency
		3,             // max attempts
		5*time.Second, // retry interval
		0,             // maxStagingSize
		"test-backend",
		rdb,
		s3,
		nil, // cache
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}
	t.Cleanup(func() {
		uploadWorker.Stop()
	})

	// Start backend LMTP server
	backendAddr := "127.0.0.1:12427"
	backendServer, err := lmtp.New(ctx, "test-backend", "localhost", backendAddr, s3, rdb, uploadWorker, lmtp.LMTPServerOptions{
		Debug: true,
	})
	if err != nil {
		t.Fatalf("Failed to create backend LMTP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		backendServer.Start(errChan)
	}()
	t.Cleanup(func() {
		// Backend has no Shutdown method, just let it close when test ends
	})

	// Wait for backend to start
	time.Sleep(200 * time.Millisecond)

	// Start LMTP proxy
	proxyAddr := "127.0.0.1:12428"
	proxyOpts := lmtpproxy.ServerOptions{
		Name:           "test-proxy",
		Addr:           proxyAddr,
		RemoteAddrs:    []string{backendAddr},
		TrustedProxies: []string{"127.0.0.1/32"}, // Allow local connections
		MaxMessageSize: 52428800,                 // advertised as SIZE, as in production
		Debug:          true,
	}

	proxy, err := lmtpproxy.New(ctx, rdb, "localhost", proxyOpts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil {
			t.Logf("LMTP proxy error: %v", err)
		}
	}()
	t.Cleanup(func() {
		proxy.Stop()
	})

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Connect to proxy
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Greeting: %s", strings.TrimSpace(greeting))

	// Send LHLO
	writer.WriteString("LHLO localhost\r\n")
	writer.Flush()

	// Read LHLO response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}
		t.Logf("LHLO: %s", strings.TrimSpace(line))
		if len(line) >= 4 && line[3] != '-' {
			break
		}
	}

	// Send MAIL FROM with the parameters the proxy advertises
	writer.WriteString("MAIL FROM:<sender@example.com> BODY=8BITMIME SIZE=1000\r\n")
	writer.Flush()

	mailResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	t.Logf("MAIL FROM: %s", strings.TrimSpace(mailResp))
	if !strings.HasPrefix(mailResp, "250") {
		t.Fatalf("MAIL FROM failed: %s", mailResp)
	}

	// RCPT TO with NOTIFY=NEVER: DSN is not announced, so the parameter is refused
	rcptCmd := fmt.Sprintf("RCPT TO:<%s> NOTIFY=NEVER\r\n", testAccount.Email)
	t.Logf("Sending: %s", strings.TrimSpace(rcptCmd))
	writer.WriteString(rcptCmd)
	writer.Flush()

	rcptResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	t.Logf("RCPT TO: %s", strings.TrimSpace(rcptResp))
	if !strings.HasPrefix(rcptResp, "555 5.5.4 ") {
		t.Errorf("RCPT TO with NOTIFY=NEVER: %q, want 555 5.5.4", strings.TrimSpace(rcptResp))
	}

	// The transaction is still open: the recipient without the parameter is taken
	rcptCmd = fmt.Sprintf("RCPT TO:<%s>\r\n", testAccount.Email)
	writer.WriteString(rcptCmd)
	writer.Flush()

	rcptResp, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	t.Logf("RCPT TO: %s", strings.TrimSpace(rcptResp))

	if !strings.HasPrefix(rcptResp, "250") {
		t.Fatalf("RCPT TO failed: %s", rcptResp)
	}

	// Send DATA
	writer.WriteString("DATA\r\n")
	writer.Flush()

	dataResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	t.Logf("DATA: %s", strings.TrimSpace(dataResp))

	if !strings.HasPrefix(dataResp, "354") {
		t.Fatalf("DATA command failed: %s", dataResp)
	}

	// Send message
	message := "From: sender@example.com\r\n" +
		"To: " + testAccount.Email + "\r\n" +
		"Subject: Test with ESMTP parameters\r\n" +
		"\r\n" +
		"This is a test message sent with BODY=8BITMIME and SIZE parameters.\r\n" +
		".\r\n"

	writer.WriteString(message)
	writer.Flush()

	// Read delivery response
	deliveryResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read delivery response: %v", err)
	}
	t.Logf("Delivery: %s", strings.TrimSpace(deliveryResp))

	if !strings.HasPrefix(deliveryResp, "250") {
		t.Fatalf("Message delivery failed: %s", deliveryResp)
	}

	// Send QUIT
	writer.WriteString("QUIT\r\n")
	writer.Flush()

	t.Log("✓ Full message delivery with ESMTP parameters succeeded")
}
