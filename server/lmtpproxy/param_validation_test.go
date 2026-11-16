package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

func startRealSoraLMTPBackend(t *testing.T, name string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	backend, err := lmtp.New(
		ctx,
		name,
		"backend.example.org",
		addr,
		&storage.S3Storage{},
		&resilient.ResilientDatabase{},
		&uploader.UploadWorker{},
		lmtp.LMTPServerOptions{TrustedNetworks: []string{"127.0.0.0/8"}},
	)
	if err != nil {
		cancel()
		t.Fatalf("lmtp.New: %v", err)
	}
	errCh := make(chan error, 1)
	go backend.Start(errCh)
	t.Cleanup(func() {
		backend.Close()
		cancel()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, dialErr := net.DialTimeout("tcp", addr, time.Second)
		if dialErr == nil {
			c.Close()
			return addr
		}
		select {
		case startErr := <-errCh:
			t.Fatalf("backend.Start: %v", startErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("backend did not listen on %s: %v", addr, dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialLMTPClient(t *testing.T, addr string) func(string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q, want 220", greeting)
	}
	send := func(line string) string {
		t.Helper()
		if _, err := io.WriteString(conn, line+"\r\n"); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
		return readReply(t, reader)
	}
	if reply := send("LHLO client.example.org"); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("LHLO = %q, want 250", reply)
	}
	return send
}

func openProxyPipeSession(t *testing.T, srv *Server) func(string) string {
	t.Helper()
	front, accepted := net.Pipe()
	sess := newSession(srv, accepted, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleConnection()
	}()
	t.Cleanup(func() {
		front.Close()
		<-done
	})
	_ = front.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(front)
	if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q, want 220", greeting)
	}
	send := func(line string) string {
		t.Helper()
		if _, err := io.WriteString(front, line+"\r\n"); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
		return readReply(t, reader)
	}
	if reply := send("LHLO client.example.org"); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("LHLO = %q, want 250", reply)
	}
	return send
}

// Valueless, empty, malformed, and duplicate XRCPTFORWARD parameters on RCPT must be
// refused at the proxy with 501 5.5.4 before routing or touching lookupCache. Previously,
// unsupportedRcptParameter checked only keyword=="XRCPTFORWARD":
//   - "XRCPTFORWARD" and "XRCPTFORWARD=" were silently stripped by parseRCPTCommand and
//     forwarded as bare RCPT TO:<addr>, getting 250 while the backend refuses them with 501;
//   - malformed values ("not-base64!", >900 decoded bytes, non-key=value pairs, empty keys)
//     were routed and forwarded to the sora LMTP backend, whose 501 5.5.4 rejection was
//     misclassified by forwardRCPT as a backend/remotelookup inconsistency, evicting the
//     recipient from lookupCache and returning 451 4.3.0;
//   - duplicate XRCPTFORWARD parameters were accepted and forwarded twice.
func TestRCPTXRCPTFORWARDValidation(t *testing.T) {
	tooLarge := base64.StdEncoding.EncodeToString([]byte("k=" + strings.Repeat("a", 899))) // 901 bytes > 900 max
	noEquals := base64.StdEncoding.EncodeToString([]byte("invalidformat\tuser=john"))
	emptyKey := base64.StdEncoding.EncodeToString([]byte("=value\tuser=john"))

	t.Run("real sora lmtp backend rejects malformed XRCPTFORWARD with 501 without 451 or cache eviction", func(t *testing.T) {
		backendAddr := startRealSoraLMTPBackend(t, "xrcptforward-real-backend")

		// Confirm the real sora LMTP backend answers 501 5.5.4 to every malformed form.
		directSend := dialLMTPClient(t, backendAddr)
		if reply := directSend("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("direct MAIL: %q", reply)
		}
		for _, p := range []string{
			"XRCPTFORWARD",
			"XRCPTFORWARD=",
			"XRCPTFORWARD=not-base64!",
			"XRCPTFORWARD=" + tooLarge,
			"XRCPTFORWARD=" + noEquals,
			"XRCPTFORWARD=" + emptyKey,
		} {
			if reply := directSend("RCPT TO:<user@example.com> " + p); !strings.HasPrefix(reply, "501 5.5.4 ") {
				t.Fatalf("direct backend RCPT with %s = %q, want 501 5.5.4", p, reply)
			}
		}
		_ = directSend("QUIT")

		srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
			Name:           "xrcptforward-real-proxy",
			RemoteAddrs:    []string{backendAddr},
			RemotePort:     24,
			ConnectTimeout: 2 * time.Second,
			MaxMessageSize: 52428800,
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

		for _, p := range []string{
			"XRCPTFORWARD=not-base64!",
			"XRCPTFORWARD=" + tooLarge,
			"XRCPTFORWARD=" + noEquals,
			"XRCPTFORWARD=" + emptyKey,
		} {
			// Seed a positive lookupCache entry before each attempt to detect eviction.
			srv.lookupCache.Set(srv.name, "user@example.com", &lookupcache.CacheEntry{
				ActualEmail:      "user@example.com",
				Result:           lookupcache.AuthSuccess,
				FromRemoteLookup: true,
			})

			reply := send("RCPT TO:<user@example.com> " + p)
			if !strings.HasPrefix(reply, "501 5.5.4 ") {
				t.Errorf("proxy RCPT with %s = %q, want 501 5.5.4", p, reply)
			}
			if cached, found := srv.lookupCache.Get(srv.name, "user@example.com"); !found || cached.IsNegative {
				t.Errorf("lookupCache for user@example.com evicted after malformed %s: found=%v, entry=%+v", p, found, cached)
			}
		}
		_ = send("QUIT")
	})

	t.Run("valueless empty malformed and duplicate XRCPTFORWARD are not stripped or routed", func(t *testing.T) {
		backend := startSoraLikeLMTPBackend(t)

		var lookupCalls atomic.Int32
		lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lookupCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
		}))
		t.Cleanup(lookup.Close)

		srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
			Name:           "xrcptforward-wire",
			RemoteAddrs:    []string{backend.addr},
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

		// Warm lookupCache with a valid recipient, then reset the transaction.
		if reply := send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("MAIL: %q", reply)
		}
		if reply := send("RCPT TO:<user@example.com>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("warm-up RCPT: %q", reply)
		}
		if got := lookupCalls.Load(); got != 1 {
			t.Fatalf("lookupCalls after warm-up = %d, want 1", got)
		}
		if reply := send("RSET"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("RSET: %q", reply)
		}

		if reply := send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250 ") {
			t.Fatalf("MAIL: %q", reply)
		}

		for _, p := range []string{
			"XRCPTFORWARD",
			"xrcptforward",
			"XRCPTFORWARD=",
			"xrcptforward=",
			"XRCPTFORWARD=not-base64!",
			"XRCPTFORWARD=" + tooLarge,
			"XRCPTFORWARD=" + noEquals,
			"XRCPTFORWARD=" + emptyKey,
			"XRCPTFORWARD=eD15 XRCPTFORWARD=eD16",
			"xrcptforward=eD15 XRCPTFORWARD=eD15",
		} {
			reply := send("RCPT TO:<user@example.com> " + p)
			if !strings.HasPrefix(reply, "501 5.5.4 ") {
				t.Errorf("RCPT with %s = %q, want 501 5.5.4", p, reply)
			}
			if cached, found := srv.lookupCache.Get(srv.name, "user@example.com"); !found || cached.IsNegative {
				t.Errorf("lookupCache evicted after %s: found=%v", p, found)
				// Re-seed so later iterations measure independently on RED.
				srv.lookupCache.Set(srv.name, "user@example.com", &lookupcache.CacheEntry{
					ActualEmail:      "user@example.com",
					Result:           lookupcache.AuthSuccess,
					FromRemoteLookup: true,
				})
			}
		}

		// Valid XRCPTFORWARD (exactly 900 bytes, escaped values, empty pairs/values) still works,
		// and uses the preserved lookupCache entry without another remotelookup request.
		maxAllowed := base64.StdEncoding.EncodeToString([]byte("k=" + strings.Repeat("a", 898))) // 900 bytes
		valid := "XRCPTFORWARD=" + maxAllowed
		if reply := send("RCPT TO:<user@example.com> " + valid); !strings.HasPrefix(reply, "250 ") {
			t.Errorf("valid 900-byte XRCPTFORWARD = %q, want 250", reply)
		}
		if got := lookupCalls.Load(); got != 1 {
			t.Errorf("remotelookup calls = %d, want 1 (positive cache entry should remain intact)", got)
		}

		wantRCPTs := []string{
			"RCPT TO:<user@example.com>",
			"RCPT TO:<user@example.com> " + valid,
		}
		if got := backend.rcptLines(); !slices.Equal(got, wantRCPTs) {
			t.Errorf("backend RCPT commands = %q, want %q", got, wantRCPTs)
		}
	})
}

// Tab-separated ESMTP parameters and quoted unbracketed addresses containing spaces or tabs
// must not bypass MAIL/RCPT parameter validation or be silently stripped.
func TestTabAndQuotedAddressParameterBypass(t *testing.T) {
	backendAddr := startRealSoraLMTPBackend(t, "tab-quote-real-backend")
	directSend := dialLMTPClient(t, backendAddr)

	// Confirm the real sora LMTP backend's replies on the same commands.
	for _, tc := range []struct {
		cmd  string
		want string
	}{
		{"MAIL FROM:<a@example.org> SIZE=10\tRET=HDRS", "555 5.5.4 "},
		{`MAIL FROM: "a@example.org RET=HDRS"`, "501 5.5.2 "},
		{"MAIL FROM:a@example.org\tRET=HDRS", "501 5.5.2 "},
	} {
		if reply := directSend(tc.cmd); !strings.HasPrefix(reply, tc.want) {
			t.Fatalf("direct backend %q = %q, want %q", tc.cmd, reply, tc.want)
		}
	}
	if reply := directSend("MAIL FROM:<a@example.org> SIZE=10\tBODY=8BITMIME\tSMTPUTF8"); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("direct backend valid tab-separated MAIL = %q, want 250", reply)
	}
	for _, tc := range []struct {
		cmd  string
		want string
	}{
		{"RCPT TO:<user@example.com> XRCPTFORWARD=eD15\tNOTIFY=NEVER", "555 5.5.4 "},
		{`RCPT TO: "user@example.com NOTIFY=NEVER"`, "501 5.1.3 "},
		{"RCPT TO:user@example.com\tNOTIFY=NEVER", "501 5.1.3 "},
	} {
		if reply := directSend(tc.cmd); !strings.HasPrefix(reply, tc.want) {
			t.Fatalf("direct backend %q = %q, want %q", tc.cmd, reply, tc.want)
		}
	}
	_ = directSend("QUIT")

	for _, maxSize := range []int64{52428800, 0} {
		t.Run(fmt.Sprintf("max_message_size=%d", maxSize), func(t *testing.T) {
			scriptedAddr, lines := scriptedLMTPBackendLines(t, map[string][]lmtpStep{
				"LHLO": {{0, "250-fake\r\n250-SIZE 52428800\r\n250 SMTPUTF8"}},
				"MAIL": {{0, "250 2.1.0 OK"}},
				"RCPT": {{0, "250 2.1.5 OK"}},
				"RSET": {{0, "250 2.0.0 OK"}},
			})

			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
			}))
			t.Cleanup(lookup.Close)

			srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
				Name:           fmt.Sprintf("tab-quote-%d", maxSize),
				RemoteAddrs:    []string{scriptedAddr},
				RemotePort:     24,
				ConnectTimeout: time.Second,
				MaxMessageSize: maxSize,
				RemoteLookup:   &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { srv.Stop() })

			send := openProxyPipeSession(t, srv)

			for _, tc := range []struct {
				cmd  string
				want string
			}{
				{"MAIL FROM:<a@example.org> SIZE=10\tRET=HDRS", "555 5.5.4 "},
				{"MAIL FROM:<a@example.org> SIZE=10\tFOO=1", "555 5.5.4 "},
				{"MAIL FROM:<a@example.org> BODY=8BITMIME\tRET=HDRS", "555 5.5.4 "},
				{`MAIL FROM: "a@example.org RET=HDRS"`, "501 5.5.2 "},
				{`MAIL FROM: "a@example.org SIZE=999999999"`, "501 5.5.2 "},
				{"MAIL FROM:\"a@example.org\tRET=HDRS\"", "501 5.5.2 "},
				{"MAIL FROM:a@example.org\tRET=HDRS", "501 5.5.2 "},
			} {
				reply := send(tc.cmd)
				if !strings.HasPrefix(reply, tc.want) {
					t.Errorf("%q = %q, want %q", tc.cmd, reply, tc.want)
					send("RSET")
				}
			}

			// Valid tab-separated supported MAIL parameters must succeed.
			if reply := send("MAIL FROM:<a@example.org> SIZE=10\tBODY=8BITMIME\tSMTPUTF8"); !strings.HasPrefix(reply, "250 ") {
				t.Errorf("valid tab-separated MAIL = %q, want 250", reply)
				if r := send("MAIL FROM:<a@example.org>"); !strings.HasPrefix(r, "250 ") {
					t.Fatalf("fallback MAIL = %q, want 250", r)
				}
			}

			for _, tc := range []struct {
				cmd  string
				want string
			}{
				{"RCPT TO:<user@example.com> XRCPTFORWARD=eD15\tNOTIFY=NEVER", "555 5.5.4 "},
				{"RCPT TO:<user@example.com> XRCPTFORWARD=eD15\tFOO=1", "555 5.5.4 "},
				{"RCPT TO:<user@example.com> XRCPTFORWARD=eD15\tXRCPTFORWARD=eD16", "501 5.5.4 "},
				{`RCPT TO: "user@example.com NOTIFY=NEVER"`, "501 5.1.3 "},
				{"RCPT TO:\"user@example.com\tNOTIFY=NEVER\"", "501 5.1.3 "},
				{"RCPT TO:user@example.com\tNOTIFY=NEVER", "501 5.1.3 "},
			} {
				reply := send(tc.cmd)
				if !strings.HasPrefix(reply, tc.want) {
					t.Errorf("%q = %q, want %q", tc.cmd, reply, tc.want)
				}
			}

			// The transaction remains open for a valid recipient, and the backend sees only
			// the canonical MAIL/RCPT from the accepted commands.
			if reply := send("RCPT TO:<user@example.com> XRCPTFORWARD=eD15"); !strings.HasPrefix(reply, "250 ") {
				t.Errorf("valid RCPT after refused tab/quoted RCPTs = %q, want 250", reply)
			}

			if reply := send("QUIT"); !strings.HasPrefix(reply, "221 ") {
				t.Errorf("QUIT = %q, want 221", reply)
			}

			var gotMail, gotRCPT []string
			for _, line := range lines() {
				switch verb, _, _ := strings.Cut(line, " "); verb {
				case "MAIL":
					gotMail = append(gotMail, line)
				case "RCPT":
					gotRCPT = append(gotRCPT, line)
				}
			}
			wantMail := []string{"MAIL FROM:<a@example.org> SIZE=10 SMTPUTF8"}
			if !slices.Equal(gotMail, wantMail) {
				t.Errorf("backend MAIL commands = %q, want %q", gotMail, wantMail)
			}
			wantRCPT := []string{"RCPT TO:<user@example.com> XRCPTFORWARD=eD15"}
			if !slices.Equal(gotRCPT, wantRCPT) {
				t.Errorf("backend RCPT commands = %q, want %q", gotRCPT, wantRCPT)
			}
		})
	}
}

// Duplicate SMTPUTF8 parameters must be refused with 501 5.5.4 (matching duplicate BODY and
// SIZE), and SIZE syntax (1*20DIGIT) plus single occurrence must be enforced even when
// max_message_size <= 0.
func TestDuplicateSMTPUTF8AndZeroLimitSizeSyntax(t *testing.T) {
	t.Run("duplicate SMTPUTF8 refused with 501", func(t *testing.T) {
		conn, r := startSizeDeclarationSession(t, 1024)
		_, _ = io.WriteString(conn, "LHLO client.example.org\r\n")
		readReply(t, r)

		for _, mail := range []string{
			"MAIL FROM:<a@example.org> SMTPUTF8 SMTPUTF8",
			"MAIL FROM:<a@example.org> smtputf8 SMTPUTF8",
			"MAIL FROM:<a@example.org> SMTPUTF8 BODY=8BITMIME SMTPUTF8",
			"MAIL FROM:<a@example.org> SMTPUTF8\tSMTPUTF8",
		} {
			_, _ = io.WriteString(conn, mail+"\r\n")
			if got := readReply(t, r); !strings.HasPrefix(got, "501 5.5.4 ") {
				t.Errorf("%s = %q, want 501 5.5.4", mail, got)
				_, _ = io.WriteString(conn, "RSET\r\n")
				readReply(t, r)
				continue
			}
			_, _ = io.WriteString(conn, "RCPT TO:<user@example.com>\r\n")
			if got := readReply(t, r); !strings.HasPrefix(got, "503 ") {
				t.Errorf("RCPT after refused %s = %q, want 503", mail, got)
			}
		}
	})

	t.Run("SIZE syntax and uniqueness checked when max_message_size is 0", func(t *testing.T) {
		conn, r := startSizeDeclarationSession(t, 0)
		_, _ = io.WriteString(conn, "LHLO client.example.org\r\n")
		readReply(t, r)

		for _, mail := range []string{
			"MAIL FROM:<a@example.org> SIZE=bogus",
			"MAIL FROM:<a@example.org> SIZE=",
			"MAIL FROM:<a@example.org> SIZE",
			"MAIL FROM:<a@example.org> SIZE=-1",
			"MAIL FROM:<a@example.org> SIZE=000000000000000000001", // 21 digits
			"MAIL FROM:<a@example.org> SIZE=10 SIZE=20",
			"MAIL FROM:<a@example.org> size=10\tSIZE=20",
		} {
			_, _ = io.WriteString(conn, mail+"\r\n")
			if got := readReply(t, r); !strings.HasPrefix(got, "501 5.5.4 ") {
				t.Errorf("%s (limit=0) = %q, want 501 5.5.4", mail, got)
				_, _ = io.WriteString(conn, "RSET\r\n")
				readReply(t, r)
				continue
			}
			_, _ = io.WriteString(conn, "RCPT TO:<user@example.com>\r\n")
			if got := readReply(t, r); !strings.HasPrefix(got, "503 ") {
				t.Errorf("RCPT after refused %s = %q, want 503", mail, got)
			}
		}

		// Valid 1*20DIGIT declarations are still accepted when limit=0.
		for _, mail := range []string{
			"MAIL FROM:<a@example.org> SIZE=104857600",
			"MAIL FROM:<a@example.org> SIZE=99999999999999999999",
		} {
			_, _ = io.WriteString(conn, mail+"\r\n")
			if got := readReply(t, r); !strings.HasPrefix(got, "250 ") {
				t.Errorf("%s (limit=0) = %q, want 250", mail, got)
			}
			_, _ = io.WriteString(conn, "RSET\r\n")
			readReply(t, r)
		}
	})
}
