//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// SMTPUTF8 (RFC 6531) at the LMTP proxy. The production bounce behind these tests was
// the proxy's own "550 5.1.3 Bad destination mailbox address syntax" for
// RCPT TO:<me+josé@dejanstrbac.com>, issued before any backend was consulted.

// recordingLMTPBackend is a scripted backend that accepts everything and records the
// MAIL FROM and RCPT TO lines it receives, optionally advertising SMTPUTF8 in LHLO.
type recordingLMTPBackend struct {
	smtputf8 bool
	mu       sync.Mutex
	envelope []string
}

func (b *recordingLMTPBackend) record(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.envelope = append(b.envelope, line)
}

func (b *recordingLMTPBackend) envelopeLines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.envelope...)
}

func (b *recordingLMTPBackend) handle(c net.Conn) {
	defer c.Close()
	rd, wr := bufio.NewReader(c), bufio.NewWriter(c)
	wr.WriteString("220 mock LMTP ready\r\n")
	wr.Flush()
	accepted := 0
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		u := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(u, "LHLO"):
			wr.WriteString("250-mock\r\n250-PIPELINING\r\n")
			if b.smtputf8 {
				wr.WriteString("250-SMTPUTF8\r\n")
			}
			wr.WriteString("250 8BITMIME\r\n")
		case strings.HasPrefix(u, "MAIL FROM"):
			b.record(line)
			accepted = 0
			wr.WriteString("250 Ok\r\n")
		case strings.HasPrefix(u, "RCPT TO"):
			b.record(line)
			accepted++
			wr.WriteString("250 Ok\r\n")
		case strings.HasPrefix(u, "DATA"):
			wr.WriteString("354 Go ahead\r\n")
			wr.Flush()
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
			}
			for i := 0; i < accepted; i++ {
				wr.WriteString("250 2.0.0 Ok: queued\r\n")
			}
		case strings.HasPrefix(u, "RSET"):
			accepted = 0
			wr.WriteString("250 Ok\r\n")
		case strings.HasPrefix(u, "QUIT"):
			wr.WriteString("221 Bye\r\n")
			wr.Flush()
			return
		default:
			wr.WriteString("250 Ok\r\n")
		}
		wr.Flush()
	}
}

func startRecordingBackend(t *testing.T, smtputf8 bool) (*recordingLMTPBackend, string) {
	t.Helper()
	b := &recordingLMTPBackend{smtputf8: smtputf8}
	addr := common.GetRandomAddress(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go b.handle(c)
		}
	}()
	return b, addr
}

// proxyTransaction runs one transaction through the proxy: LHLO, MAIL FROM (mailFromArgs
// is the raw text after "MAIL FROM:", e.g. "<josé@sender.example> SMTPUTF8"), RCPT TO,
// DATA. It returns the LHLO lines and the MAIL, RCPT and end-of-data replies, stopping
// at the first reply that is not 250.
func proxyTransaction(t *testing.T, proxyAddr, mailFromArgs, rcpt string) (lhlo []string, mailResp, rcptResp, dataResp string) {
	t.Helper()
	return proxyTransactionMessage(t, proxyAddr, mailFromArgs, rcpt, "Subject: smtputf8\r\n\r\nbody")
}

// proxyTransactionMessage is proxyTransaction with the message (headers and body, CRLF
// separated, without the final dot) chosen by the caller.
func proxyTransactionMessage(t *testing.T, proxyAddr, mailFromArgs, rcpt, message string) (lhlo []string, mailResp, rcptResp, dataResp string) {
	t.Helper()
	c, err := NewLMTPClient(proxyAddr)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer c.Close()

	if err := c.SendCommand("LHLO localhost"); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	if lhlo, err = c.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO response: %v", err)
	}
	if err := c.SendCommand("MAIL FROM:" + mailFromArgs); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if mailResp, err = c.ReadResponse(); err != nil {
		t.Fatalf("MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(mailResp, "250") {
		return
	}
	if err := c.SendCommand("RCPT TO:<" + rcpt + ">"); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	if rcptResp, err = c.ReadResponse(); err != nil {
		t.Fatalf("RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(rcptResp, "250") {
		return
	}
	if err := c.SendCommand("DATA"); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if resp, err := c.ReadResponse(); err != nil || !strings.HasPrefix(resp, "354") {
		t.Fatalf("DATA response: %q, %v", resp, err)
	}
	if err := c.SendCommand(message + "\r\n."); err != nil {
		t.Fatalf("send message: %v", err)
	}
	if dataResp, err = c.ReadResponse(); err != nil {
		t.Fatalf("end-of-data response: %v", err)
	}
	return
}

func requireEnvelope(t *testing.T, b *recordingLMTPBackend, want ...string) {
	t.Helper()
	got := b.envelopeLines()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("backend received envelope:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func requireProxyAccepted(t *testing.T, mailResp, rcptResp, dataResp string) {
	t.Helper()
	for what, resp := range map[string]string{"MAIL FROM": mailResp, "RCPT TO": rcptResp, "end-of-data": dataResp} {
		if !strings.HasPrefix(resp, "250") {
			t.Fatalf("%s must be accepted, got %q (MAIL %q, RCPT %q, DATA %q)", what, resp, mailResp, rcptResp, dataResp)
		}
	}
}

// RFC 6531 §3.1: the proxy, being the server the MTA talks to, announces SMTPUTF8.
func TestLMTPProxy_SMTPUTF8_Advertised(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	_, backendAddr := startRecordingBackend(t, true)
	var lookups atomic.Int32
	proxyAddr := startTransactionProxy(t, backendAddr, &lookups)

	lhlo, _, _, _ := proxyTransaction(t, proxyAddr, "<sender@example.com>", "user@example.com")
	for _, l := range lhlo {
		if strings.HasSuffix(strings.TrimSpace(l), "SMTPUTF8") {
			return
		}
	}
	t.Fatalf("proxy LHLO must advertise SMTPUTF8, got:\n%s", strings.Join(lhlo, "\n"))
}

// An internationalized envelope — non-ASCII sender AND a non-ASCII base local part the
// remote lookup is queried for — passes the proxy's syntax gate and is forwarded with
// the SMTPUTF8 parameter to a backend that advertised the extension.
func TestLMTPProxy_SMTPUTF8_ForwardedToCapableBackend(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	b, backendAddr := startRecordingBackend(t, true)
	var lookups atomic.Int32
	proxyAddr := startTransactionProxy(t, backendAddr, &lookups)

	_, mailResp, rcptResp, dataResp := proxyTransaction(t, proxyAddr, "<josé@sender.example> SMTPUTF8", "josé@example.com")
	requireProxyAccepted(t, mailResp, rcptResp, dataResp)
	requireEnvelope(t, b,
		"MAIL FROM:<josé@sender.example> SMTPUTF8",
		"RCPT TO:<josé@example.com>",
	)
	if lookups.Load() != 1 {
		t.Fatalf("the non-ASCII recipient must have been looked up exactly once, got %d", lookups.Load())
	}
}

// A backend that does not advertise SMTPUTF8 (an older sora) gets the plain MAIL command:
// the parameter is downgraded rather than sent to a server that would answer 504, so a
// mixed-version deployment keeps delivering.
func TestLMTPProxy_SMTPUTF8_DowngradedForLegacyBackend(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	b, backendAddr := startRecordingBackend(t, false)
	var lookups atomic.Int32
	proxyAddr := startTransactionProxy(t, backendAddr, &lookups)

	_, mailResp, rcptResp, dataResp := proxyTransaction(t, proxyAddr, "<josé@sender.example> SMTPUTF8", "user+josé@example.com")
	requireProxyAccepted(t, mailResp, rcptResp, dataResp)
	requireEnvelope(t, b,
		"MAIL FROM:<josé@sender.example>",
		"RCPT TO:<user+josé@example.com>",
	)
}

// The production case: the MTA never negotiated SMTPUTF8 and sent an ASCII sender with a
// non-ASCII +detail recipient. The proxy accepts it, detects the internationalized
// envelope from the recipient, and tells a capable backend so with the parameter.
func TestLMTPProxy_SMTPUTF8_AutodetectedFromRecipient(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	b, backendAddr := startRecordingBackend(t, true)
	var lookups atomic.Int32
	proxyAddr := startTransactionProxy(t, backendAddr, &lookups)

	_, mailResp, rcptResp, dataResp := proxyTransaction(t, proxyAddr, "<sender@example.com>", "me+josé@dejanstrbac.com")
	requireProxyAccepted(t, mailResp, rcptResp, dataResp)
	requireEnvelope(t, b,
		"MAIL FROM:<sender@example.com> SMTPUTF8",
		"RCPT TO:<me+josé@dejanstrbac.com>",
	)
}

// Malformed UTF-8 is still a permanent syntax error at the proxy, before any backend
// is consulted.
func TestLMTPProxy_SMTPUTF8_MalformedUTF8IsPermanent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	b, backendAddr := startRecordingBackend(t, true)
	var lookups atomic.Int32
	proxyAddr := startTransactionProxy(t, backendAddr, &lookups)

	_, _, rcptResp, _ := proxyTransaction(t, proxyAddr, "<sender@example.com>", "me+jos\xe9@dejanstrbac.com")
	if !strings.HasPrefix(rcptResp, "550 5.1.3") {
		t.Fatalf("malformed UTF-8 recipient must be rejected with 550 5.1.3, got %q", rcptResp)
	}
	if got := b.envelopeLines(); len(got) != 0 {
		t.Fatalf("nothing may reach the backend for a rejected recipient, got %q", got)
	}
}
