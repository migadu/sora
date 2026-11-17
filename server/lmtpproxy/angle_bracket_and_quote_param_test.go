package lmtpproxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
)

func tapBackendConnections(t *testing.T, targetAddr string) (tapAddr string, connCount func() int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var conns atomic.Int32
	go func() {
		for {
			inConn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				outConn, dialErr := net.DialTimeout("tcp", targetAddr, 2*time.Second)
				if dialErr != nil {
					return
				}
				defer outConn.Close()
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(outConn, c)
					_ = outConn.Close()
					close(done)
				}()
				_, _ = io.Copy(c, outConn)
				_ = c.Close()
				<-done
			}(inConn)
		}
	}()

	return ln.Addr().String(), conns.Load
}

func TestExtractAddressAngleBracketRejection(t *testing.T) {
	invalid := []string{
		"user@example.com@>",
		"user@example.com@>FOO=1",
		"user@example.com@>XRCPTFORWARD=eD15",
		`"user@example.com@>"`,
		"sender@example.org>",
		`"sender@example.org>"`,
		"sender@example.org> FOO=1",
		"<a<b@example.org>",
		`"<a<b@example.org>"`,
		"<user@example.com@<a@b>",
		`<"unclosed@example.org>`,
		`<"a b"@example.org>`,
		`"<a b@example.org>"`,
	}
	for _, input := range invalid {
		if got, ok := extractAddressString(input); ok {
			t.Errorf("extractAddressString(%q) = (%q, true), want (\"\", false)", input, got)
		}
	}
}

// Case 1A: RCPT TO addresses containing '<' or '>' (e.g. RCPT TO:user@example.com@>,
// RCPT TO:user@example.com@>FOO=1, RCPT TO:user@example.com@>XRCPTFORWARD=eD15,
// RCPT TO:"user@example.com@>") must be refused immediately with 501 5.1.3 before
// lookupCache or backend contact, instead of hitting lookupCache for BaseAddress(),
// sending RCPT TO:<user@example.com@>> to server/lmtp (which answers 555/501),
// evicting user@example.com from lookupCache, and returning 451 4.3.0.
func TestRCPTAngleBracketInjectionRefusedBeforeLookupAndBackend(t *testing.T) {
	realBackendAddr := startRealSoraLMTPBackend(t, "rcpt-angle-real-backend")
	tappedBackendAddr, backendConns := tapBackendConnections(t, realBackendAddr)

	badRCPTs := []string{
		"RCPT TO:user@example.com@>",
		"RCPT TO:user@example.com@tok>",
		"RCPT TO:user@example.com@>FOO=1",
		"RCPT TO:user@example.com@>XRCPTFORWARD=eD15",
		`RCPT TO:"user@example.com@>"`,
		"RCPT TO:user@example.com>",
		"RCPT TO:<a<b@example.org>",
		`RCPT TO:"<a<b@example.org>"`,
	}

	// Confirm the real sora LMTP backend refuses these forms with 501 5.1.3.
	directSend := dialLMTPClient(t, realBackendAddr)
	if reply := directSend("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("direct MAIL: %q", reply)
	}
	for _, cmd := range badRCPTs {
		// On the backend, unquoted TO:"<a<b@example.org>" is also a 501 5.1.3 path syntax error.
		if reply := directSend(cmd); !strings.HasPrefix(reply, "501 5.1.3 ") {
			t.Fatalf("direct backend %q = %q, want 501 5.1.3", cmd, reply)
		}
	}
	_ = directSend("QUIT")

	var lookupCalls atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookupCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
	}))
	t.Cleanup(lookup.Close)

	srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
		Name:           "rcpt-angle-injection-proxy",
		RemoteAddrs:    []string{tappedBackendAddr},
		RemotePort:     24,
		ConnectTimeout: 2 * time.Second,
		MaxMessageSize: 52428800,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled: true,
			URL:     lookup.URL + "?email=$email",
			Timeout: "2s",
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         100,
			CleanupInterval: "5m",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Stop() })

	send := openProxyPipeSession(t, srv)
	if reply := send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("proxy MAIL: %q", reply)
	}

	for _, cmd := range append(badRCPTs, "RCPT TO:<user@example.com@<a@b>") {
		// Seed positive lookupCache entry before each attempt to detect eviction.
		srv.lookupCache.Set(srv.name, "user@example.com", &lookupcache.CacheEntry{
			ActualEmail:      "user@example.com",
			Result:           lookupcache.AuthSuccess,
			FromRemoteLookup: true,
		})

		reply := send(cmd)
		if !strings.HasPrefix(reply, "501 5.1.3 ") {
			t.Errorf("proxy %q = %q, want 501 5.1.3", cmd, reply)
		}
		if cached, found := srv.lookupCache.Get(srv.name, "user@example.com"); !found || cached.IsNegative {
			t.Errorf("lookupCache for user@example.com evicted after %q: found=%v, entry=%+v", cmd, found, cached)
		}
	}

	if got := lookupCalls.Load(); got != 0 {
		t.Errorf("remotelookup calls = %d, want 0", got)
	}
	if got := backendConns(); got != 0 {
		t.Errorf("backend connections dialed = %d, want 0", got)
	}
	_ = send("QUIT")
}

// Case 1B: MAIL FROM addresses containing '<' or '>' (e.g. MAIL FROM:sender@example.org>,
// MAIL FROM:"sender@example.org>", MAIL FROM:<a<b@example.org>) must be refused up front
// with 501 5.5.2 instead of returning 250 and later sending MAIL FROM:<sender@example.org>>
// to the backend (555 5.5.4), tearing down held and freshly dialed backend connections,
// and returning 451 4.4.1.
func TestMAILAngleBracketInjectionRefusedWithoutBackendTeardown(t *testing.T) {
	badMAILs := []string{
		"MAIL FROM:sender@example.org>",
		"MAIL FROM:sender@example.org>FOO=1",
		`MAIL FROM:"sender@example.org>"`,
		"MAIL FROM:<a<b@example.org>",
		`MAIL FROM:"<a<b@example.org>"`,
	}

	t.Run("real sora lmtp backend", func(t *testing.T) {
		realBackendAddr := startRealSoraLMTPBackend(t, "mail-angle-real-backend")
		tappedBackendAddr, backendConns := tapBackendConnections(t, realBackendAddr)

		directSend := dialLMTPClient(t, realBackendAddr)
		for _, cmd := range badMAILs {
			if reply := directSend(cmd); !strings.HasPrefix(reply, "501 5.5.2 ") {
				t.Fatalf("direct backend %q = %q, want 501 5.5.2", cmd, reply)
			}
		}
		_ = directSend("QUIT")

		lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
		}))
		t.Cleanup(lookup.Close)

		srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
			Name:           "mail-angle-real-proxy",
			RemoteAddrs:    []string{tappedBackendAddr},
			RemotePort:     24,
			ConnectTimeout: 2 * time.Second,
			MaxMessageSize: 52428800,
			RemoteLookup: &config.RemoteLookupConfig{
				Enabled: true,
				URL:     lookup.URL + "?email=$email",
				Timeout: "2s",
			},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { srv.Stop() })

		send := openProxyPipeSession(t, srv)
		for _, cmd := range badMAILs {
			reply := send(cmd)
			if !strings.HasPrefix(reply, "501 5.5.2 ") {
				t.Errorf("proxy %q = %q, want 501 5.5.2", cmd, reply)
			}
			// A pipelined RCPT after the refused MAIL must get 503 without dialing a backend.
			rcptReply := send("RCPT TO:<user@example.com>")
			if !strings.HasPrefix(rcptReply, "503 5.5.1 ") {
				t.Errorf("RCPT after %q = %q, want 503 5.5.1", cmd, rcptReply)
			}
			if strings.HasPrefix(reply, "250 ") {
				_ = send("RSET")
			}
		}

		if got := backendConns(); got != 0 {
			t.Errorf("backend connections dialed = %d, want 0", got)
		}
		_ = send("QUIT")
	})

	t.Run("preserves held backend connection across transactions", func(t *testing.T) {
		soraBackend := startSoraLikeLMTPBackend(t)
		tappedBackendAddr, backendConns := tapBackendConnections(t, soraBackend.addr)

		lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
		}))
		t.Cleanup(lookup.Close)

		srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
			Name:           "mail-angle-held-proxy",
			RemoteAddrs:    []string{tappedBackendAddr},
			RemotePort:     24,
			ConnectTimeout: 2 * time.Second,
			MaxMessageSize: 52428800,
			RemoteLookup: &config.RemoteLookupConfig{
				Enabled: true,
				URL:     lookup.URL + "?email=$email",
				Timeout: "2s",
			},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { srv.Stop() })

		send := openProxyPipeSession(t, srv)

		// Establish and hold backend connection #1.
		if reply := send("MAIL FROM:<good@example.org>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("initial MAIL: %q", reply)
		}
		if reply := send("RCPT TO:<user@example.com>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("initial RCPT: %q", reply)
		}
		if reply := send("RSET"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("RSET: %q", reply)
		}
		if got := backendConns(); got != 1 {
			t.Fatalf("backend connections after warm-up = %d, want 1", got)
		}

		// Angle-injected MAIL must fail immediately with 501 5.5.2 without dropping the held backend.
		if reply := send("MAIL FROM:sender@example.org>"); !strings.HasPrefix(reply, "501 5.5.2 ") {
			t.Errorf("MAIL FROM:sender@example.org> = %q, want 501 5.5.2", reply)
			_ = send("RCPT TO:<user@example.com>")
			_ = send("RSET")
		} else {
			if rcptReply := send("RCPT TO:<user@example.com>"); !strings.HasPrefix(rcptReply, "503 5.5.1 ") {
				t.Errorf("RCPT after refused MAIL = %q, want 503 5.5.1", rcptReply)
			}
		}

		// Subsequent valid transaction must reuse held connection #1 (still connCount == 1).
		if reply := send("MAIL FROM:<good2@example.org>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("second valid MAIL: %q", reply)
		}
		if reply := send("RCPT TO:<user@example.com>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("second valid RCPT: %q", reply)
		}
		if got := backendConns(); got != 1 {
			t.Errorf("backend connections after second valid transaction = %d, want 1 (held backend must not be torn down)", got)
		}
		_ = send("QUIT")
	})
}

// Case 1C & Case 2: Verify against a real sora LMTP backend that:
//   - Angle-bracket path syntax errors precede ESMTP parameter refusals (501 5.5.2 /
//     501 5.1.3 rather than 555 5.5.4 / 552 5.3.4).
//   - Post-path ESMTP parameters are tokenized with RFC 5321 strings.Fields rather
//     than IMAP-style ParseLine quote grouping (no 500 on unclosed quotes in ESMTP
//     parameters, and 501 5.5.4 rather than 555 5.5.4 when spaces inside quotes hide
//     empty-value or duplicate-keyword parameters).
func TestAngleBracketOrderAndQuotedESMTPParamsMatchBackend(t *testing.T) {
	mailCases := []struct {
		cmd  string
		want string
	}{
		// Case 1C: path validation precedes ESMTP parameter refusal.
		{"MAIL FROM:sender@example.org> FOO=1", "501 5.5.2 "},
		{"MAIL FROM:<a<b@example.org> FOO=1", "501 5.5.2 "},
		{`MAIL FROM:"sender@example.org>" FOO=1`, "501 5.5.2 "},
		{"MAIL FROM:sender@example.org> SIZE=99999999999999999999", "501 5.5.2 "},

		// Case 2: unclosed quotes in ESMTP parameters or after FROM: must not get 500.
		{`MAIL FROM:<a@example.org> "SIZE=`, "501 5.5.4 "},
		{`MAIL FROM:<a@example.org> "FOO=1`, "555 5.5.4 "},
		{`MAIL FROM:<a@example.org> SIZE=abc "FOO=1`, "501 5.5.4 "},
		{`MAIL FROM:<a@example.org> SIZE=99999999999999999999 "FOO=1`, "552 5.3.4 "},
		{`MAIL FROM: "unclosed@example.org`, "501 5.5.2 "},

		// Case 2: quoted ESMTP tokens containing spaces + empty-value or duplicate keywords.
		{`MAIL FROM:<a@example.org> "FOO=1 SIZE= "`, "501 5.5.4 "},
		{`MAIL FROM:<a@example.org> " FOO=1 FOO=2"`, "501 5.5.4 "},
		{`MAIL FROM:<a@example.org> " SIZE=10 SIZE=20"`, "501 5.5.4 "},
	}

	rcptCases := []struct {
		cmd  string
		want string
	}{
		// Case 1C: path validation precedes ESMTP parameter refusal.
		{"RCPT TO:user@example.com> FOO=1", "501 5.1.3 "},
		{"RCPT TO:user@example.com@> FOO=1", "501 5.1.3 "},
		{"RCPT TO:<a<b@example.org> FOO=1", "501 5.1.3 "},
		{`RCPT TO:"user@example.com@>" FOO=1`, "501 5.1.3 "},

		// Case 2: unclosed quotes in ESMTP parameters or after TO: must not get 500.
		{`RCPT TO:<b@example.org> "FOO=1`, "555 5.5.4 "},
		{`RCPT TO:<b@example.org> "XRCPTFORWARD=`, "501 5.5.4 "},
		{`RCPT TO:<b@example.org> XRCPTFORWARD=!!! "FOO=1`, "501 5.5.4 "},
		{`RCPT TO: "unclosed@example.org`, "501 5.1.3 "},

		// Case 2: quoted ESMTP tokens containing spaces + empty-value or duplicate keywords.
		{`RCPT TO:<b@example.org> "FOO=1 BAR= "`, "501 5.5.4 "},
		{`RCPT TO:<b@example.org> " FOO=1 FOO=2"`, "501 5.5.4 "},
		{`RCPT TO:<b@example.org> " XRCPTFORWARD=eD15 xrcptforward=eD16"`, "501 5.5.4 "},
	}

	check := func(t *testing.T, send func(string) string) {
		t.Helper()
		for _, tc := range mailCases {
			reply := send(tc.cmd)
			if strings.HasPrefix(reply, "250 ") {
				_ = send("RSET")
			}
			if !strings.HasPrefix(reply, tc.want) {
				t.Errorf("%q = %q, want %q", tc.cmd, reply, tc.want)
			}
		}
		if reply := send("MAIL FROM:<a@example.org>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("MAIL: %q", reply)
		}
		for _, tc := range rcptCases {
			reply := send(tc.cmd)
			if !strings.HasPrefix(reply, tc.want) {
				t.Errorf("%q = %q, want %q", tc.cmd, reply, tc.want)
			}
		}
		_ = send("QUIT")
	}

	backendAddr := startRealSoraLMTPBackend(t, "angle-quote-parity-backend")
	t.Run("backend", func(t *testing.T) {
		check(t, dialLMTPClient(t, backendAddr))
	})
	t.Run("proxy", func(t *testing.T) {
		srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
			Name:           "angle-quote-parity-proxy",
			RemoteAddrs:    []string{backendAddr},
			RemotePort:     24,
			ConnectTimeout: 2 * time.Second,
			MaxMessageSize: 52428800,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { srv.Stop() })
		check(t, openProxyPipeSession(t, srv))
	})
}
