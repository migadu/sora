package server

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// seriesWith returns the series of family whose labels include all of labels.
func seriesWith(t *testing.T, family string, labels map[string]string) []*dto.Metric {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var out []*dto.Metric
	for _, mf := range mfs {
		if mf.GetName() != family {
			continue
		}
	series:
		for _, m := range mf.GetMetric() {
			for name, value := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == name && lp.GetValue() == value {
						found = true
					}
				}
				if !found {
					continue series
				}
			}
			out = append(out, m)
		}
	}
	return out
}

// TestSessionLockMetricsUseLowercaseProtocol: MutexTimeoutHelper times the lock on a
// session's own state, not a mailbox lock, so its metrics are named after the session.
// Their protocol label is lowercase like every other metric's ("imap", not "IMAP"),
// whatever the caller passes.
func TestSessionLockMetricsUseLowercaseProtocol(t *testing.T) {
	var mu sync.RWMutex
	h := NewMutexTimeoutHelper(&mu, context.Background(), "IMAP", nil)

	if ok, release := h.AcquireWriteLockWithTimeout(context.Background()); !ok {
		t.Fatal("uncontended write lock not acquired")
	} else {
		release()
	}
	if ok, release := h.AcquireReadLockWithTimeout(context.Background()); !ok {
		t.Fatal("uncontended read lock not acquired")
	} else {
		release()
	}
	// A read lock given up while another holder keeps the write lock.
	mu.Lock()
	cancelled, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	ok, release := h.AcquireReadLockWithTimeout(cancelled)
	release()
	cancel()
	mu.Unlock()
	if ok {
		t.Fatal("contended read lock acquired after its context ended")
	}

	for _, c := range []struct {
		family string
		labels map[string]string
	}{
		{"sora_session_lock_duration_seconds", map[string]string{"protocol": "imap", "lock_type": "write", "result": "success"}},
		{"sora_session_lock_duration_seconds", map[string]string{"protocol": "imap", "lock_type": "read", "result": "success"}},
		{"sora_session_lock_duration_seconds", map[string]string{"protocol": "imap", "lock_type": "read", "result": "timeout"}},
		{"sora_session_lock_timeouts_total", map[string]string{"protocol": "imap", "lock_type": "read"}},
	} {
		if len(seriesWith(t, c.family, c.labels)) == 0 {
			t.Errorf("no %s series with %v", c.family, c.labels)
		}
	}
	for _, family := range []string{"sora_session_lock_duration_seconds", "sora_session_lock_timeouts_total", "sora_mailbox_lock_duration_seconds", "sora_mailbox_lock_timeouts_total"} {
		if got := seriesWith(t, family, map[string]string{"protocol": "IMAP"}); len(got) > 0 {
			t.Errorf("%s has %d series with protocol=\"IMAP\"", family, len(got))
		}
	}
}

// TestSearchRateLimiterProtocolLabelIsLowercase: a refusal is counted in
// sora_protocol_errors_total under the same lowercase protocol as the protocol's
// other errors, whatever the caller passes.
func TestSearchRateLimiterProtocolLabelIsLowercase(t *testing.T) {
	limiter := NewSearchRateLimiter("IMAP", 1, time.Hour, 0)
	t.Cleanup(limiter.Stop)

	count := func(protocol string) float64 {
		var sum float64
		for _, m := range seriesWith(t, "sora_protocol_errors_total", map[string]string{
			"protocol": protocol, "command": "SEARCH", "error_type": "rate_limited",
		}) {
			sum += m.GetCounter().GetValue()
		}
		return sum
	}
	lower0, upper0 := count("imap"), count("IMAP")

	refused := 0
	for i := 0; i < 3; i++ {
		if limiter.CanSearch(context.Background(), 294) != nil {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("no search refused; the test does not exercise the limit")
	}
	if d := count("imap") - lower0; d != float64(refused) {
		t.Errorf(`protocol="imap" grew by %v after %d refusals, want %d`, d, refused, refused)
	}
	if d := count("IMAP") - upper0; d != 0 {
		t.Errorf(`protocol="IMAP" grew by %v, want 0`, d)
	}
}

// checkProtocolLabels fails unless each of families has one series for serverName,
// labelled protocol=want.
func checkProtocolLabels(t *testing.T, families []string, serverName, want string) {
	t.Helper()
	var got []string
	ok := true
	for _, family := range families {
		series := seriesWith(t, family, map[string]string{"server_name": serverName})
		if len(series) != 1 {
			ok = false
		}
		for _, m := range series {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "protocol" {
					got = append(got, lp.GetValue())
					ok = ok && lp.GetValue() == want
				}
			}
		}
	}
	if !ok {
		t.Errorf("server_name=%q: protocol = %q, want %q in each family", serverName, got, want)
	}
}

// TestAuthRateLimiterMetricsUseServerType: the rate limiter's gauges label protocol with
// the lowercase server type the other metrics use. The name a server gives its limiter
// keys the limiter's cluster gossip, so it stays as it is and only the label is mapped.
func TestAuthRateLimiterMetricsUseServerType(t *testing.T) {
	families := []string{
		"sora_auth_rate_limiter_ip_username_entries",
		"sora_auth_rate_limiter_ip_entries",
		"sora_auth_rate_limiter_username_entries",
		"sora_auth_rate_limiter_blocked_ips",
	}
	cfg := DefaultAuthRateLimiterConfig()
	cfg.Enabled = true
	cfg.CleanupInterval = time.Hour

	// The names the servers give NewAuthRateLimiter*.
	for name, want := range map[string]string{
		"IMAP":           "imap",
		"POP3":           "pop3",
		"ManageSieve":    "managesieve",
		"IMAP-PROXY":     "imap_proxy",
		"POP3-PROXY":     "pop3_proxy",
		"SIEVE-PROXY":    "managesieve_proxy",
		"user-api":       "userapi",
		"USER-API-PROXY": "userapi_proxy",
	} {
		t.Run(name, func(t *testing.T) {
			serverName := "limiter-711-" + name
			limiter := NewAuthRateLimiter(name, serverName, "mail.example.com", cfg)
			defer limiter.Stop()
			checkProtocolLabels(t, families, serverName, want) // set by the constructor

			limiter.cleanupExpiredEntries() // and by the periodic update
			checkProtocolLabels(t, families, serverName, want)
		})
	}
}

// TestConnectionTrackerMetricsUseServerType: a connection tracker's gauges label
// protocol with the server type it serves. A proxy's tracker has the protocol's name like
// a backend's (it keys the tracker's gossip and the Admin API's tracker list), so the
// proxy constructor is what tells the two apart.
func TestConnectionTrackerMetricsUseServerType(t *testing.T) {
	families := []string{
		"sora_connection_tracker_users",
		"sora_connection_tracker_instance_ids",
		"sora_connection_tracker_ips",
		"sora_connection_tracker_broadcast_queue_size",
	}
	for _, c := range []struct {
		name  string
		proxy bool
		want  string
	}{
		{"IMAP", false, "imap"},
		{"POP3", false, "pop3"},
		{"ManageSieve", false, "managesieve"},
		{"IMAP", true, "imap_proxy"},
		{"POP3", true, "pop3_proxy"},
		{"ManageSieve", true, "managesieve_proxy"},
		{"LMTP", true, "lmtp_proxy"},
	} {
		t.Run(c.want, func(t *testing.T) {
			serverName := "tracker-711-" + c.want
			newTracker := NewConnectionTracker
			if c.proxy {
				newTracker = NewProxyConnectionTracker
			}
			tracker := newTracker(c.name, serverName, "mail.example.com", serverName, nil, 0, 0, 0, false)
			defer tracker.Stop()
			tracker.cleanup()
			checkProtocolLabels(t, families, serverName, c.want)
		})
	}
}

// serverTypeOf returns the protocol label of the metrics of the server in package dir
// (a directory under server/): "imap", "imap_proxy", "userapi", ...
func serverTypeOf(dir string) string {
	if base, ok := strings.CutSuffix(dir, "proxy"); ok && base != "" {
		return base + "_proxy"
	}
	return dir
}

// TestAuthDelayCallersLabelTheServerType: every server passes ApplyAuthenticationDelay
// (or ApplyHTTPAuthenticationDelay) its own server type, the protocol label its other
// metrics use, so the sora_auth_delay_* series join them by protocol.
func TestAuthDelayCallersLabelTheServerType(t *testing.T) {
	files, err := filepath.Glob("*/*.go")
	if err != nil {
		t.Fatal(err)
	}
	// The index of the protocol argument of each delay function.
	protocolArg := map[string]int{"ApplyAuthenticationDelay": 3, "ApplyHTTPAuthenticationDelay": 4}
	fset := token.NewFileSet()
	calls := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		want := serverTypeOf(filepath.Base(filepath.Dir(path)))
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			i, ok := protocolArg[sel.Sel.Name]
			if !ok || len(call.Args) <= i {
				return true
			}
			calls++
			arg := call.Args[i]
			if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if got, _ := strconv.Unquote(lit.Value); got == want {
					return true
				}
			}
			t.Errorf("%s: %s(..., %s), want %q", fset.Position(call.Pos()), sel.Sel.Name, types.ExprString(arg), want)
			return true
		})
	}
	if calls == 0 {
		t.Fatal("no ApplyAuthenticationDelay call found under server/")
	}
	t.Logf("%d calls checked", calls)
}
