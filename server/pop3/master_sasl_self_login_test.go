package pop3

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMasterSASLSelfLoginRepliesAlike: a master SASL self-login, whose authorization
// identity and authentication identity are both the (non-address) master SASL
// username, is answered and counted the same whether or not the password is the
// master SASL password, with or without master_sasl_allowed_networks. The correct
// password enters the master SASL block, where the target does not parse or the
// gate refuses the peer; any other password falls through to regular
// authentication (an authorization identity equal to the authentication identity
// asks for no impersonation), where the username does not parse. Two different
// replies told a client that knows the master SASL username whether a guessed
// master SASL password is correct.
func TestMasterSASLSelfLoginRepliesAlike(t *testing.T) {
	for _, gate := range []struct {
		name     string
		networks []string
	}{
		{"no_allowed_networks", nil},
		// The session below runs on a net.Pipe, whose peer is in no network.
		{"peer_outside_allowed_networks", []string{"192.0.2.0/24"}},
	} {
		t.Run(gate.name, func(t *testing.T) {
			name := "master-sasl-self-login-" + gate.name
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			limiter := &unparseableLoginLimiter{}
			srv, err := New(ctx, name, "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, POP3ServerOptions{
				InsecureAuth:              true,
				Config:                    &config.Config{},
				MasterSASLUsername:        "proxyuser",
				MasterSASLPassword:        "master-sasl-secret",
				MasterSASLAllowedNetworks: gate.networks,
				AuthLimiterOverride:       limiter,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(srv.Close)

			type outcome struct {
				reply            string
				checks, failures int32
				counted          float64
			}
			attempt := func(password string) outcome {
				c1, c2 := net.Pipe()
				defer c1.Close()
				defer c2.Close()
				sctx, scancel := context.WithCancel(ctx)
				defer scancel()
				s := &POP3Session{server: srv, conn: c1, deleted: make(map[int]bool), ctx: sctx, cancel: scancel}
				s.Protocol = "POP3"
				s.ServerName = srv.name
				s.HostName = srv.hostname
				s.RemoteIP = "127.0.0.1"
				s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, sctx, "POP3", s.InfoLog)

				counter := metrics.AuthenticationAttempts.WithLabelValues("pop3", name, "localhost", "failure")
				checks, failures, counted := limiter.checks.Load(), limiter.failures.Load(), testutil.ToFloat64(counter)
				err := s.AuthenticatePlain(ctx, "proxyuser", "proxyuser", password)
				return outcome{
					reply:    fmt.Sprintf("%#v", err),
					checks:   limiter.checks.Load() - checks,
					failures: limiter.failures.Load() - failures,
					counted:  testutil.ToFloat64(counter) - counted,
				}
			}

			wrong := attempt("wrong")
			correct := attempt("master-sasl-secret")
			if wrong != correct {
				t.Errorf("master SASL self-login answered differently by password:\n  wrong password:  %+v\n  master password: %+v", wrong, correct)
			}
			if want := fmt.Sprintf("%#v", errAuthFailed); wrong.reply != want {
				t.Errorf("wrong password: %s, want the bad-credential reply %s", wrong.reply, want)
			}
			if want := (outcome{reply: wrong.reply, checks: 1, failures: 1, counted: 1}); wrong != want {
				t.Errorf("wrong password: %+v, want one rate-limit check, one recorded failure and one counted failure", wrong)
			}
		})
	}
}
