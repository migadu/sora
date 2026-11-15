package lmtp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// startWireBackend runs an LMTP backend on a loopback port for tests that stay before
// the database: the greeting, LHLO, MAIL, and RCPT up to address parsing.
func startWireBackend(t *testing.T, name string, opts LMTPServerOptions) (*LMTPServerBackend, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	opts.TrustedNetworks = []string{"127.0.0.0/8"}
	b, err := New(ctx, name, "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, opts)
	if err != nil {
		cancel()
		t.Fatalf("New: %v", err)
	}
	errCh := make(chan error, 1)
	go b.Start(errCh)
	t.Cleanup(func() {
		b.Close()
		cancel()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return b, addr
		}
		select {
		case err := <-errCh:
			t.Fatalf("Start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("LMTP backend not listening on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type wireClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func newWireClient(t *testing.T, conn net.Conn) *wireClient {
	t.Helper()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	c := &wireClient{t: t, conn: conn, r: bufio.NewReader(conn)}
	t.Cleanup(func() { conn.Close() })
	if greeting := c.reply(); !strings.HasPrefix(greeting[0], "220 ") {
		t.Fatalf("greeting: %q", greeting)
	}
	return c
}

// reply reads one, possibly multiline, reply.
func (c *wireClient) reply() []string {
	c.t.Helper()
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("reading reply after %q: %v", lines, err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			return lines
		}
	}
}

func (c *wireClient) cmd(line string) []string {
	c.t.Helper()
	fmt.Fprintf(c.conn, "%s\r\n", line)
	return c.reply()
}

func dialWire(t *testing.T, addr string) *wireClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return newWireClient(t, conn)
}

// sizeKeyword returns the SIZE line of an LHLO reply, without the reply code.
func sizeKeyword(lhlo []string) string {
	for _, line := range lhlo {
		if keyword := line[4:]; keyword == "SIZE" || strings.HasPrefix(keyword, "SIZE ") {
			return keyword
		}
	}
	return ""
}

// RFC 1870 section 4: "If a numeric parameter follows the SIZE keyword value of the EHLO
// response, it indicates the size of the largest message that the server is willing to
// accept." Section 7: a server with a fixed limit "must accept the extended MAIL command and
// return a 552 reply code if the client's declared size exceeds its fixed size limit".
// The backend has one (max_message_size, 50 MiB by default), so LHLO names it and MAIL
// refuses a larger declaration before the body is sent; a reload changes both.
func TestLHLOAdvertisesAndMAILEnforcesMessageSizeLimit(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		_, addr := startWireBackend(t, "size-default", LMTPServerOptions{})
		c := dialWire(t, addr)
		want := fmt.Sprintf("SIZE %d", DefaultMaxMessageSize)
		if got := sizeKeyword(c.cmd("LHLO client.example.org")); got != want {
			t.Fatalf("LHLO advertises %q, want %q", got, want)
		}
		if resp := c.cmd(fmt.Sprintf("MAIL FROM:<a@example.org> SIZE=%d", 2*DefaultMaxMessageSize)); !strings.HasPrefix(resp[0], "552 5.3.4 ") {
			t.Fatalf("MAIL with SIZE over the default limit: %q, want 552 5.3.4", resp)
		}
	})

	t.Run("configured and reloaded", func(t *testing.T) {
		b, addr := startWireBackend(t, "size-configured", LMTPServerOptions{MaxMessageSize: 1024})
		c := dialWire(t, addr)
		if got := sizeKeyword(c.cmd("LHLO client.example.org")); got != "SIZE 1024" {
			t.Fatalf("LHLO advertises %q, want SIZE 1024", got)
		}
		if resp := c.cmd("MAIL FROM:<a@example.org> SIZE=1025"); !strings.HasPrefix(resp[0], "552 5.3.4 ") {
			t.Fatalf("MAIL SIZE=1025 over a limit of 1024: %q, want 552 5.3.4", resp)
		}
		if resp := c.cmd("MAIL FROM:<a@example.org> SIZE=1024"); !strings.HasPrefix(resp[0], "250 ") {
			t.Fatalf("MAIL SIZE=1024 at a limit of 1024: %q, want 250", resp)
		}

		if err := b.ReloadConfig(config.ServerConfig{Name: "size-configured", Type: "lmtp", MaxMessageSize: "2kb"}); err != nil {
			t.Fatal(err)
		}
		c = dialWire(t, addr)
		if got := sizeKeyword(c.cmd("LHLO client.example.org")); got != "SIZE 2048" {
			t.Fatalf("LHLO after reloading max_message_size = 2kb advertises %q, want SIZE 2048", got)
		}
		if resp := c.cmd("MAIL FROM:<a@example.org> SIZE=2048"); !strings.HasPrefix(resp[0], "250 ") {
			t.Fatalf("MAIL SIZE=2048 after the reload: %q, want 250", resp)
		}
	})
}

// go-smtp's DATA reader refuses a body over the limit with smtp.ErrDataTooLarge. That is
// the permanent 552 5.3.4 (RFC 3463 X.3.4 "Message too big for system"), not a read error
// answered with a 4xx that has the client retry the same message.
func TestDataReportsLibrarySizeRefusalAs552(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := New(ctx, "size-refusal", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, LMTPServerOptions{
		MaxMessageSize: 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sender, _ := server.NewAddress("sender@example.com")
	rcpt, _ := server.NewAddress("user@example.com")
	s := &LMTPSession{backend: b, ctx: ctx, startTime: time.Now(), sender: &sender}
	s.Protocol = "LMTP"
	s.User = server.NewUser(rcpt, 1)
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, ctx, "LMTP", nil)

	err = s.Data(ctx, &tooLargeReader{remaining: 1024})
	if se, ok := err.(*smtp.SMTPError); !ok || se.Code != 552 || se.EnhancedCode != (smtp.EnhancedCode{5, 3, 4}) {
		t.Fatalf("DATA refused by the library for size: %v, want 552 5.3.4", err)
	}
}

// tooLargeReader yields remaining octets, then smtp.ErrDataTooLarge, as go-smtp's DATA
// reader does for a body over Server.MaxMessageBytes.
type tooLargeReader struct{ remaining int }

func (r *tooLargeReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, smtp.ErrDataTooLarge
	}
	n := min(len(p), r.remaining)
	for i := range p[:n] {
		p[i] = 'x'
	}
	r.remaining -= n
	return n, nil
}

// A syntactically invalid recipient: RFC 5321 section 4.2.2 has "553 Requested action not
// taken: mailbox name not allowed (e.g., mailbox syntax incorrect)", listed for RCPT in
// section 4.3.2, and RFC 3463 has X.1.3 "Bad destination mailbox address syntax". 513 is no
// SMTP reply code, and X.0.1 no enhanced status code ("X.0.0 ... is the only undefined
// error code", RFC 3463 section 3.1).
func TestRCPTInvalidSyntaxIs553_5_1_3(t *testing.T) {
	_, addr := startWireBackend(t, "rcpt-syntax", LMTPServerOptions{})
	c := dialWire(t, addr)
	c.cmd("LHLO client.example.org")
	if resp := c.cmd("MAIL FROM:<a@example.org>"); !strings.HasPrefix(resp[0], "250 ") {
		t.Fatalf("MAIL: %q", resp)
	}
	resp := c.cmd(`RCPT TO:<"john doe"@example.com>`)
	if !strings.HasPrefix(resp[0], "553 5.1.3 ") {
		t.Fatalf("RCPT of a syntactically invalid address: %q, want 553 5.1.3", resp)
	}
}
