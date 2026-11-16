package lmtpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/config"
)

type rcptWireBackend struct {
	addr string

	mu    sync.Mutex
	lines []string
}

func (b *rcptWireBackend) rcptLines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, line := range b.lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 4 && strings.EqualFold(trimmed[:4], "RCPT") {
			out = append(out, line)
		}
	}
	return out
}

type rcptRecordingListener struct {
	net.Listener
	record func(string)
}

func (l *rcptRecordingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &rcptRecordingConn{Conn: conn, record: l.record}, nil
}

type rcptRecordingConn struct {
	net.Conn
	record func(string)
	mu     sync.Mutex
	buf    bytes.Buffer
}

func (c *rcptRecordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.buf.Write(p[:n])
		for {
			data := c.buf.Bytes()
			idx := bytes.IndexByte(data, '\n')
			if idx < 0 {
				break
			}
			line := strings.TrimRight(string(data[:idx+1]), "\r\n")
			c.buf.Next(idx + 1)
			c.record(line)
		}
		c.mu.Unlock()
	}
	return n, err
}

type soraLikeSMTPBackend struct{}

func (soraLikeSMTPBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &soraLikeSMTPSession{}, nil
}

type soraLikeSMTPSession struct{}

func (s *soraLikeSMTPSession) Mail(_ context.Context, _ string, _ *smtp.MailOptions) error {
	return nil
}

func (s *soraLikeSMTPSession) Rcpt(_ context.Context, to string, opts *smtp.RcptOptions) error {
	// Match server/lmtp/session.go: go-smtp rejects NOTIFY/ORCPT/RRVS with 555 and
	// syntax/unbracketed-with-params/unclosed-quote with 501; LMTPSession.Rcpt rejects
	// any remaining unknown extension parameter other than XRCPTFORWARD with 555 5.5.4.
	if opts != nil {
		for keyword := range opts.Extensions {
			if keyword != "XRCPTFORWARD" {
				return &smtp.SMTPError{
					Code:         555,
					EnhancedCode: smtp.EnhancedCode{5, 5, 4},
					Message:      "Unknown RCPT parameter",
				}
			}
		}
	}
	switch strings.ToLower(to) {
	case "user@example.com", "real@example.com", "real+tag@example.com":
		return nil
	default:
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 1, 1},
			Message:      "No such user here",
		}
	}
}

func (s *soraLikeSMTPSession) Data(_ context.Context, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

func (s *soraLikeSMTPSession) Reset()        {}
func (s *soraLikeSMTPSession) Logout() error { return nil }

func startSoraLikeLMTPBackend(t *testing.T) *rcptWireBackend {
	t.Helper()
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wb := &rcptWireBackend{addr: rawLn.Addr().String()}
	recLn := &rcptRecordingListener{
		Listener: rawLn,
		record: func(line string) {
			wb.mu.Lock()
			wb.lines = append(wb.lines, line)
			wb.mu.Unlock()
		},
	}

	srv := smtp.NewServer(soraLikeSMTPBackend{})
	srv.Domain = "backend.example.org"
	srv.LMTP = true
	srv.EnableXCLIENT = true
	srv.EnableRCPTExtensions = true
	srv.EnableSMTPUTF8 = true

	go func() {
		_ = srv.Serve(recLn)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = rawLn.Close()
	})
	return wb
}

// TestRCPTCanonicalForwardingToSoraBackend verifies that every RCPT TO form accepted
// by lmtpproxy (extra/leading/tab whitespace before TO:, quoted "<addr>" or "addr",
// bare unbracketed addr, and remotelookup alias rewrites) is forwarded to the LMTP
// backend in canonical "RCPT TO:<recipient>" form with unsupported ESMTP parameters
// stripped and valid XRCPTFORWARD preserved, without triggering backend 500/501/555
// rejections, false 451 4.3.0 replies, or lookupCache eviction.
func TestRCPTCanonicalForwardingToSoraBackend(t *testing.T) {
	validXrcpt := "XRCPTFORWARD=" + base64.StdEncoding.EncodeToString([]byte("user=fwd@example.com"))

	tests := []struct {
		name            string
		rcptCmd         string
		wantBackendRCPT string
		wantCachedKey   string
	}{
		{
			name:            "extra spaces before TO: with unknown parameter",
			rcptCmd:         "RCPT  TO:<user@example.com> FOO=1",
			wantBackendRCPT: "RCPT TO:<user@example.com>",
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "extra spaces before TO: with DSN parameters",
			rcptCmd:         "RCPT  TO:<user@example.com> NOTIFY=SUCCESS ORCPT=rfc822;user@example.com",
			wantBackendRCPT: "RCPT TO:<user@example.com>",
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "space and tab before TO: with unknown parameter",
			rcptCmd:         "RCPT \tTO:<user@example.com> FOO=1",
			wantBackendRCPT: "RCPT TO:<user@example.com>",
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "leading space before RCPT with unknown parameter",
			rcptCmd:         " RCPT TO:<user@example.com> FOO=1",
			wantBackendRCPT: "RCPT TO:<user@example.com>",
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "quoted bracketed TO: path",
			rcptCmd:         `RCPT TO:"<user@example.com>"`,
			wantBackendRCPT: "RCPT TO:<user@example.com>",
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "quoted bracketed TO: path with unknown and XRCPTFORWARD parameters",
			rcptCmd:         `RCPT TO:"<user@example.com>" FOO=1 ` + validXrcpt,
			wantBackendRCPT: "RCPT TO:<user@example.com> " + validXrcpt,
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "quoted bracketed TO: path after space with DSN parameter",
			rcptCmd:         `RCPT TO: "<user@example.com>" NOTIFY=NEVER`,
			wantBackendRCPT: "RCPT TO:<user@example.com>",
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "unbracketed recipient with unknown parameter",
			rcptCmd:         "RCPT TO:user@example.com FOO=1",
			wantBackendRCPT: "RCPT TO:<user@example.com>",
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "unbracketed recipient with DSN and XRCPTFORWARD",
			rcptCmd:         "RCPT TO:user@example.com NOTIFY=NEVER " + validXrcpt,
			wantBackendRCPT: "RCPT TO:<user@example.com> " + validXrcpt,
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "quoted bare recipient",
			rcptCmd:         `RCPT TO:"user@example.com"`,
			wantBackendRCPT: "RCPT TO:<user@example.com>",
			wantCachedKey:   "user@example.com",
		},
		{
			name:            "remotelookup alias rewrite with extra spaces and unknown parameter",
			rcptCmd:         "RCPT  TO:<alias+tag@example.com> FOO=1",
			wantBackendRCPT: "RCPT TO:<real+tag@example.com>",
			wantCachedKey:   "alias@example.com",
		},
		{
			name:            "remotelookup alias rewrite on unbracketed recipient with XRCPTFORWARD",
			rcptCmd:         "RCPT TO:alias+tag@example.com FOO=1 " + validXrcpt,
			wantBackendRCPT: "RCPT TO:<real+tag@example.com> " + validXrcpt,
			wantCachedKey:   "alias@example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend := startSoraLikeLMTPBackend(t)

			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				email := strings.ToLower(r.URL.Query().Get("email"))
				switch email {
				case "user@example.com":
					_ = json.NewEncoder(w).Encode(map[string]any{"address": "user@example.com"})
				case "alias@example.com":
					_ = json.NewEncoder(w).Encode(map[string]any{"address": "real@example.com"})
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(lookup.Close)

			srv, err := New(context.Background(), nil, "proxy.example.org", ServerOptions{
				Name:           "rcpt-canonical-" + tc.name,
				RemoteAddrs:    []string{backend.addr},
				RemotePort:     24,
				ConnectTimeout: 2 * time.Second,
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

			front, accepted := net.Pipe()
			t.Cleanup(func() { front.Close() })
			sess := newSession(srv, accepted, nil)
			done := make(chan struct{})
			go func() {
				defer close(done)
				sess.handleConnection()
			}()

			front.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(front)
			if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
				t.Fatalf("greeting = %q, want 220", greeting)
			}

			send := func(line string) string {
				t.Helper()
				if _, err := fmt.Fprintf(front, "%s\r\n", line); err != nil {
					t.Fatalf("writing %q: %v", line, err)
				}
				return readReply(t, reader)
			}

			if reply := send("LHLO client.example.org"); !strings.HasPrefix(reply, "250 ") {
				t.Fatalf("LHLO = %q, want 250", reply)
			}
			if reply := send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(reply, "250 ") {
				t.Fatalf("MAIL FROM = %q, want 250", reply)
			}

			rcptReply := send(tc.rcptCmd)
			if !strings.HasPrefix(rcptReply, "250 ") {
				t.Errorf("RCPT (%q) = %q, want 250 (backend received %v)", tc.rcptCmd, rcptReply, backend.rcptLines())
			}

			gotRCPTs := backend.rcptLines()
			if len(gotRCPTs) != 1 || gotRCPTs[0] != tc.wantBackendRCPT {
				t.Errorf("backend received RCPT lines %q, want [%q]", gotRCPTs, tc.wantBackendRCPT)
			}

			if cached, found := srv.lookupCache.Get(srv.name, tc.wantCachedKey); !found || cached.IsNegative {
				t.Errorf("lookupCache entry for %q after RCPT: found=%v, entry=%+v; want positive cached entry preserved", tc.wantCachedKey, found, cached)
			}

			if strings.HasPrefix(rcptReply, "250 ") {
				if reply := send("DATA"); !strings.HasPrefix(reply, "354 ") {
					t.Fatalf("DATA = %q, want 354", reply)
				}
				if reply := send("Subject: test\r\n\r\nhello\r\n."); !strings.HasPrefix(reply, "250 ") {
					t.Fatalf("end-of-data = %q, want 250", reply)
				}
			}

			if reply := send("QUIT"); !strings.HasPrefix(reply, "221 ") {
				t.Errorf("QUIT = %q, want 221", reply)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("session did not finish after QUIT")
			}
		})
	}
}
