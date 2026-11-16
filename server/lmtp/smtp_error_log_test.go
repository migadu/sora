package lmtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// What go-smtp reports through its ErrorLog (a failed STARTTLS, a recovered panic)
// is a record of the configured logger, in its format and output, with the remote
// address as an attribute (#1443). Before, the ErrorLog was a log.Logger on
// logger.Stderr(): a plain "smtp/server <date> STARTTLS error from ..." line in a
// JSON log file, and only on stderr with output = "syslog".
func TestSTARTTLSFailureIsALogRecord(t *testing.T) {
	for _, tt := range []struct {
		name string
		// send runs after LHLO; the server must fail the STARTTLS.
		send    func(t *testing.T, conn net.Conn, r *bufio.Reader)
		wantMsg string
	}{
		{
			name: "plain text instead of a ClientHello",
			send: func(t *testing.T, conn net.Conn, r *bufio.Reader) {
				io.WriteString(conn, "STARTTLS\r\n")
				if line := readReplyLine(t, r); !strings.HasPrefix(line, "220 ") {
					t.Fatalf("STARTTLS: %q", line)
				}
				io.WriteString(conn, "MAIL FROM:<sender@example.com>\r\n")
			},
			wantMsg: "handshake failed",
		},
		{
			name: "plain text pipelined behind STARTTLS",
			send: func(t *testing.T, conn net.Conn, r *bufio.Reader) {
				io.WriteString(conn, "STARTTLS\r\nMAIL FROM:<sender@example.com>\r\n")
			},
			wantMsg: "buffered bytes before TLS handshake",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureJSONLogs(t)
			addr := startSTARTTLSBackend(t, "starttls-errorlog")

			conn := dialFirstConnection(t, addr)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(conn)
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "220 ") {
				t.Fatalf("greeting: %q", line)
			}
			io.WriteString(conn, "LHLO client.example.com\r\n")
			for {
				line := readReplyLine(t, r)
				if !strings.HasPrefix(line, "250") {
					t.Fatalf("LHLO: %q", line)
				}
				if strings.HasPrefix(line, "250 ") {
					break
				}
			}
			tt.send(t, conn, r)

			remote := conn.LocalAddr().String()
			rec := waitForRecord(t, logs, func(rec map[string]any) bool {
				msg, _ := rec["msg"].(string)
				return strings.Contains(msg, "STARTTLS") && strings.Contains(msg, tt.wantMsg)
			})
			if rec["level"] != "WARN" {
				t.Errorf("level = %v, want WARN: %v", rec["level"], rec)
			}
			if rec["remote"] != remote {
				t.Errorf("remote = %v, want %s: %v", rec["remote"], remote, rec)
			}
			if rec["name"] != "starttls-errorlog" {
				t.Errorf("name = %v, want the server's name: %v", rec["name"], rec)
			}
		})
	}
}

// A panic go-smtp recovers in a connection is a server bug: an ERROR record naming
// the connection, not a plain line beside the log records.
func TestSMTPErrorLogRecoveredPanicIsAnError(t *testing.T) {
	logs := captureJSONLogs(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b, err := New(ctx, "panic-errorlog", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, LMTPServerOptions{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// As go-smtp's Conn.handle and Conn.handlePanic report it.
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 40000}
	b.server.ErrorLog.Printf("panic serving %v: %v\n%s", remote, "boom", "goroutine 1 [running]:\nmain.main()")

	rec := waitForRecord(t, logs, func(rec map[string]any) bool {
		msg, _ := rec["msg"].(string)
		return strings.Contains(msg, "panic serving") && strings.Contains(msg, "boom")
	})
	if rec["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR: %v", rec["level"], rec)
	}
	if rec["remote"] != "192.0.2.7:40000" {
		t.Errorf("remote = %v, want 192.0.2.7:40000: %v", rec["remote"], rec)
	}
	if msg, _ := rec["msg"].(string); !strings.Contains(msg, "goroutine 1 [running]") {
		t.Errorf("the record lost the stack: %v", rec)
	}
}

// captureJSONLogs makes a JSON logger at DEBUG the global logger until the test ends,
// as [logging] format = "json" does.
func captureJSONLogs(t *testing.T) *reloadLogs {
	t.Helper()
	logs := &reloadLogs{}
	prev := logger.Swap(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { logger.Swap(prev) })
	return logs
}

// waitForRecord returns the first record in logs that match accepts, waiting up to
// three seconds for it. Every line of logs must be a JSON record.
func waitForRecord(t *testing.T, logs *reloadLogs, match func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
			if line == "" {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("the JSON log has a line that is not JSON (%v): %q", err, line)
			}
			if match(rec) {
				return rec
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no such record; the configured logger got:\n%s", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startSTARTTLSBackend starts an LMTP backend offering STARTTLS on a plain
// listener, stopped when the test ends.
func startSTARTTLSBackend(t *testing.T, name string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	b, err := New(ctx, name, "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, LMTPServerOptions{
		TLS:            true,
		TLSUseStartTLS: true,
		TLSConfig:      &tls.Config{Certificates: []tls.Certificate{selfSignedTestCert(t)}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go b.Start(make(chan error, 1))
	t.Cleanup(func() { b.Close() })
	return addr
}
