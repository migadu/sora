package imap

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAuthorizationRefusalNeedsCredentials: an AUTHENTICATE PLAIN that asks to act as
// another user with a wrong password is answered and counted like any other bad
// credential, whether or not its authentication identity is the master SASL username.
// RFC 4616 section 2 verifies the authentication identity and password first and the
// authorization identity second, so only a client whose credentials checked out may be
// told it cannot act as somebody else. Refusing every other authentication identity
// before the password, unrecorded, while the master SASL username got the
// bad-credential reply and a recorded failure, confirmed a guessed master SASL username
// to anyone who could reach the port.
func TestAuthorizationRefusalNeedsCredentials(t *testing.T) {
	const name = "authz-refusal-needs-credentials"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	limiter := &unparseableLoginLimiter{}
	srv, err := New(ctx, name, "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, IMAPServerOptions{
		InsecureAuth:        true,
		AppendLimit:         DefaultAppendLimit,
		MaxConnections:      10,
		Config:              &config.Config{},
		MasterSASLUsername:  []byte("proxyuser"),
		MasterSASLPassword:  []byte("master-sasl-secret"),
		AuthLimiterOverride: limiter,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)

	type outcome struct {
		reply            string
		checks, failures int32
		counted          float64
	}
	attempt := func(authcid string) outcome {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(c)
		readTagged(t, r, "* OK")

		counter := metrics.AuthenticationAttempts.WithLabelValues("imap", name, "localhost", "failure")
		checks, failures, counted := limiter.checks.Load(), limiter.failures.Load(), testutil.ToFloat64(counter)
		c.Write([]byte("a AUTHENTICATE PLAIN\r\n"))
		readTagged(t, r, "+")
		c.Write([]byte(base64.StdEncoding.EncodeToString([]byte("victim@example.com\x00"+authcid+"\x00wrong")) + "\r\n"))
		reply := strings.TrimSpace(readTagged(t, r, "a "))
		return outcome{
			reply:    reply,
			checks:   limiter.checks.Load() - checks,
			failures: limiter.failures.Load() - failures,
			counted:  testutil.ToFloat64(counter) - counted,
		}
	}

	master := attempt("proxyuser")
	other := attempt("notmaster")
	if master != other {
		t.Errorf("wrong password answered differently by authentication identity:\n  master SASL username: %+v\n  other username:       %+v", master, other)
	}
	if want := (outcome{reply: "a NO [AUTHENTICATIONFAILED] " + authFailedError().Text, checks: 1, failures: 1, counted: 1}); other != want {
		t.Errorf("other username, wrong password: %+v, want %+v (the bad-credential reply, one rate-limit check, one recorded and one counted failure)", other, want)
	}
}
