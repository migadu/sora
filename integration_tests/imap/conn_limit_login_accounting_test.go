//go:build integration

package imap_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	serverPkg "github.com/migadu/sora/server"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIMAP_MaxConnectionsPerUserRefusalAccounting verifies that logins refused
// over max_connections_per_user across all IMAP authentication paths (regular
// LOGIN, master-username LOGIN, regular AUTHENTICATE PLAIN, master-username
// AUTHENTICATE PLAIN, and master-SASL AUTHENTICATE PLAIN):
//   - answer NO [LIMIT] and leave the session unauthenticated;
//   - log no "authentication successful" line, and log "connection registration
//     rejected" with address=<email> and without user=<email>;
//   - increment neither sora_authentication_attempts_total{result="success"}
//     nor {result="failure"}, nor sora_domain_connections_total;
//   - keep sora_authenticated_connections_current and authenticatedConnections
//     at 1 while the first session is open and return both to 0 on logout.
func TestIMAP_MaxConnectionsPerUserRefusalAccounting(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	ts := common.GetTimestamp()
	domain := fmt.Sprintf("connlimit-%d.example", ts)
	account := common.CreateTestAccountWithEmail(t, rdb, "alice@"+domain, "s3cur3p4ss!")
	accountID, err := rdb.GetAccountIDByEmailWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("GetAccountIDByEmailWithRetry: %v", err)
	}

	address := common.GetRandomAddress(t)
	name := fmt.Sprintf("test-imap-connlimit-%d", ts)
	const hostname = "localhost"

	srv, err := serverImap.New(
		context.Background(),
		name,
		hostname,
		address,
		&storage.S3Storage{},
		rdb,
		nil,
		nil,
		serverImap.IMAPServerOptions{
			InsecureAuth:       true,
			MasterUsername:     []byte(masterUsername),
			MasterPassword:     []byte(masterPassword),
			MasterSASLUsername: []byte(masterSASLUsername),
			MasterSASLPassword: []byte(masterSASLPassword),
		},
	)
	if err != nil {
		t.Fatalf("imap.New: %v", err)
	}

	tracker := serverPkg.NewConnectionTracker("IMAP", name, hostname, "test-imap-connlimit-instance", nil, 1, 0, 0, false)
	t.Cleanup(tracker.Stop)
	srv.SetConnTracker(tracker)

	go func() {
		if err := srv.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP server stopped: %v", err)
		}
	}()
	t.Cleanup(srv.Close)

	for deadline := time.Now().Add(5 * time.Second); ; {
		conn, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("IMAP listener did not become ready: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	succ := metrics.AuthenticationAttempts.WithLabelValues("imap", name, hostname, "success")
	fail := metrics.AuthenticationAttempts.WithLabelValues("imap", name, hostname, "failure")
	authConns := metrics.AuthenticatedConnectionsCurrent.WithLabelValues("imap", name, hostname)
	domainConns := metrics.DomainConnectionCount.WithLabelValues("imap", domain)

	dial := func(t *testing.T) *imapclient.Client {
		t.Helper()
		c, err := imapclient.DialInsecure(address, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if err := c.WaitGreeting(); err != nil {
			t.Fatalf("greeting: %v", err)
		}
		return c
	}

	// Positive control 1: bad password increments failure=1, success=0, domain=0.
	{
		logs := common.CaptureLogs(t)
		s0, f0, d0 := testutil.ToFloat64(succ), testutil.ToFloat64(fail), testutil.ToFloat64(domainConns)
		bad := dial(t)
		err := bad.Login(account.Email, "wrong-password").Wait()
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) || imapErr.Code != imap.ResponseCodeAuthenticationFailed {
			t.Fatalf("bad LOGIN: %v, want NO [AUTHENTICATIONFAILED]", err)
		}
		if ds, df, dd := testutil.ToFloat64(succ)-s0, testutil.ToFloat64(fail)-f0, testutil.ToFloat64(domainConns)-d0; ds != 0 || df != 1 || dd != 0 {
			t.Fatalf("bad LOGIN deltas = (success=%v, failure=%v, domain=%v), want (0, 1, 0)", ds, df, dd)
		}
		common.RequireLoginResults(t, logs, account.Email,
			[]string{"protocol=IMAP-" + name, "address=" + account.Email, `msg="authentication failed"`},
		)
		_ = bad.Close()
	}

	// Positive control 2: admitted login takes the user's single slot and increments success=1, domain=1.
	first := dial(t)
	{
		logs := common.CaptureLogs(t)
		s0, f0, d0 := testutil.ToFloat64(succ), testutil.ToFloat64(fail), testutil.ToFloat64(domainConns)
		if err := first.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("first LOGIN: %v", err)
		}
		if ds, df, dd := testutil.ToFloat64(succ)-s0, testutil.ToFloat64(fail)-f0, testutil.ToFloat64(domainConns)-d0; ds != 1 || df != 0 || dd != 1 {
			t.Fatalf("first LOGIN deltas = (success=%v, failure=%v, domain=%v), want (1, 0, 1)", ds, df, dd)
		}
		if got := testutil.ToFloat64(authConns); got != 1 {
			t.Fatalf("AuthenticatedConnectionsCurrent after first LOGIN = %v, want 1", got)
		}
		if got := srv.GetAuthenticatedConnections(); got != 1 {
			t.Fatalf("authenticatedConnections after first LOGIN = %d, want 1", got)
		}
		common.RequireLoginResults(t, logs, account.Email,
			[]string{"protocol=IMAP-" + name, "user=" + account.Email, `msg="authentication successful"`},
		)
	}

	// Every IMAP authentication path must refuse a second session over max_connections_per_user
	// without logging "authentication successful" or incrementing success/failure/domain metrics.
	refusedCases := []struct {
		name  string
		login func(c *imapclient.Client) error
	}{
		{
			name: "LOGIN",
			login: func(c *imapclient.Client) error {
				return c.Login(account.Email, account.Password).Wait()
			},
		},
		{
			name: "LOGIN_master_username",
			login: func(c *imapclient.Client) error {
				return c.Login(account.Email+"@"+masterUsername, masterPassword).Wait()
			},
		},
		{
			name: "AUTHENTICATE_PLAIN",
			login: func(c *imapclient.Client) error {
				return c.Authenticate(sasl.NewPlainClient("", account.Email, account.Password))
			},
		},
		{
			name: "AUTHENTICATE_PLAIN_master_username",
			login: func(c *imapclient.Client) error {
				return c.Authenticate(sasl.NewPlainClient("", account.Email+"@"+masterUsername, masterPassword))
			},
		},
		{
			name: "AUTHENTICATE_PLAIN_master_SASL",
			login: func(c *imapclient.Client) error {
				return c.Authenticate(&plainSASLClient{
					identity: account.Email,
					username: masterSASLUsername,
					password: masterSASLPassword,
				})
			},
		},
	}

	for _, tc := range refusedCases {
		t.Run(tc.name, func(t *testing.T) {
			logs := common.CaptureLogs(t)
			s0, f0, d0 := testutil.ToFloat64(succ), testutil.ToFloat64(fail), testutil.ToFloat64(domainConns)

			over := dial(t)
			err := tc.login(over)
			var imapErr *imap.Error
			if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != imap.ResponseCodeLimit {
				t.Fatalf("%s over max_connections_per_user = %v, want NO [LIMIT]", tc.name, err)
			}

			// The session must remain unauthenticated after the refusal.
			if _, selErr := over.Select("INBOX", nil).Wait(); selErr == nil {
				t.Fatalf("SELECT INBOX succeeded on connection-limited session after %s", tc.name)
			}

			if ds, df := testutil.ToFloat64(succ)-s0, testutil.ToFloat64(fail)-f0; ds != 0 || df != 0 {
				t.Errorf("%s AuthenticationAttempts deltas = (success=%v, failure=%v), want (0, 0)", tc.name, ds, df)
			}
			if dd := testutil.ToFloat64(domainConns) - d0; dd != 0 {
				t.Errorf("%s DomainConnectionCount delta = %v, want 0", tc.name, dd)
			}
			if got := testutil.ToFloat64(authConns); got != 1 {
				t.Errorf("%s AuthenticatedConnectionsCurrent = %v, want 1", tc.name, got)
			}
			if got := srv.GetAuthenticatedConnections(); got != 1 {
				t.Errorf("%s authenticatedConnections = %d, want 1", tc.name, got)
			}
			if got := tracker.GetConnectionCount(accountID); got != 1 {
				t.Errorf("%s tracker connection count = %d, want 1", tc.name, got)
			}

			rejLine := logs.WaitForLine(t, `msg="connection registration rejected"`, "protocol=IMAP-"+name, "remote=", "session=")
			if !strings.Contains(rejLine, "address="+account.Email) {
				t.Errorf("%s rejection log lacks address=%s:\n%s", tc.name, account.Email, rejLine)
			}
			if strings.Contains(rejLine, "user="+account.Email) {
				t.Errorf("%s rejection log attributes session to authenticated user=%s:\n%s", tc.name, account.Email, rejLine)
			}

			// Closing the refused connection must release nothing from the first session's slot.
			_ = over.Logout().Wait()
			_ = over.Close()
			logs.WaitForLine(t, `msg="unauthenticated connection dropped"`)

			if got := tracker.GetConnectionCount(accountID); got != 1 {
				t.Errorf("%s tracker connection count after refused close = %d, want 1", tc.name, got)
			}

			// Refused login must emit zero login-result lines ("authentication successful", etc.).
			common.RequireLoginResults(t, logs, account.Email)
		})
	}

	// Once the first session logs out, authenticated counts and tracker slots return to 0,
	// and a new login succeeds normally.
	if err := first.Logout().Wait(); err != nil {
		t.Fatalf("first LOGOUT: %v", err)
	}
	_ = first.Close()

	for deadline := time.Now().Add(5 * time.Second); ; {
		if srv.GetAuthenticatedConnections() == 0 && testutil.ToFloat64(authConns) == 0 && tracker.GetConnectionCount(accountID) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after first session logout: authenticatedConnections=%d gauge=%v tracked=%d, want all 0",
				srv.GetAuthenticatedConnections(), testutil.ToFloat64(authConns), tracker.GetConnectionCount(accountID))
		}
		time.Sleep(10 * time.Millisecond)
	}

	after := dial(t)
	s0, f0 := testutil.ToFloat64(succ), testutil.ToFloat64(fail)
	if err := after.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("LOGIN after slot freed: %v", err)
	}
	if ds, df := testutil.ToFloat64(succ)-s0, testutil.ToFloat64(fail)-f0; ds != 1 || df != 0 {
		t.Errorf("admitted LOGIN after slot freed deltas = (success=%v, failure=%v), want (1, 0)", ds, df)
	}
}
