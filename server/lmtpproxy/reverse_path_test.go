package lmtpproxy

import (
	"io"
	"strings"
	"testing"
)

// RFC 5321 section 4.1.2: "Reverse-path = Path / "<>"". Only "<>" is the null
// reverse-path. A MAIL whose reverse-path the proxy cannot read is refused as a sora
// backend refuses it on a direct connection, "501 5.5.2 Was expecting MAIL arg syntax
// of FROM:<address>" (go-smtp's reply; "501 Syntax error in command or arguments" may
// answer any command, section 4.3.2), and starts no transaction. It must never reach a
// backend as "MAIL FROM:<>": the message would be stored as a bounce, which Sieve
// "envelope :from" and vacation (which never answers a null sender) then see.
func TestUnreadableReversePathRefused(t *testing.T) {
	for _, tt := range []struct{ name, from string }{
		{"no closing bracket", "<foo"},
		{"one character", "x"},
		{"quoted local part with space", `<"john doe"@example.org>`},
		{"spaces inside brackets", "< a@example.org >"},
		// Not "<>": a quoted string is a local part (section 4.1.2), and this one has
		// no domain. A sora backend answers it as the other cases here.
		{"quoted null path", `"<>"`},
		{"quoted null path after a space", ` "<>"`},
		{"trailing text after null path", "<>@example.org"},
		{"second path after null path", "<><sender@example.org>"},
		{"extra closing bracket after null path", "<>>"},
		{"trailing text after path", "<sender@example.org>@other.org"},
		{"quoted local part with inner closing bracket", `<"alice@evil.com>"@example.org>`},
		{"unseparated parameter after path", "<sender@example.org>SIZE=999999999"},
		{"quoted path with trailing text", `"<user@example.com> foo"`},
		{"quoted path with trailing text after a space", ` "<user@example.com> foo"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			backend := startNestedMailBackend(t)
			conn, reader, _ := startNestedMailProxySession(t, backend.addr)
			send := func(cmd string) string {
				t.Helper()
				if _, err := io.WriteString(conn, cmd+"\r\n"); err != nil {
					t.Fatalf("writing %q: %v", cmd, err)
				}
				return readReply(t, reader)
			}

			if got := send("LHLO client.example.com"); !strings.HasPrefix(got, "250 ") {
				t.Fatalf("LHLO: %q, want 250", got)
			}
			want := "501 5.5.2 Was expecting MAIL arg syntax of FROM:<address>"
			if got := send("MAIL FROM:" + tt.from); got != want {
				t.Errorf("MAIL FROM:%s: %q, want %q", tt.from, got, want)
			}
			// No transaction was started: the recipient a pipelining MTA sends on is out
			// of sequence, and no message is delivered.
			if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "503 5.5.1 ") {
				t.Errorf("RCPT after the refused MAIL: %q, want 503 5.5.1", got)
			}
			// Nothing reached a backend (the scripted one records a command before replying).
			for _, cmd := range backend.commands() {
				t.Errorf("backend was sent %q for MAIL FROM:%s", cmd, tt.from)
			}

			// The session goes on: a readable MAIL starts a transaction.
			if got := send("MAIL FROM:<sender@example.com>"); !strings.HasPrefix(got, "250 ") {
				t.Fatalf("MAIL after the refused one: %q, want 250", got)
			}
			if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "250 ") {
				t.Fatalf("RCPT: %q, want 250", got)
			}
			if got := send("DATA"); !strings.HasPrefix(got, "354 ") {
				t.Fatalf("DATA: %q, want 354", got)
			}
			wantDelivered := "250 2.0.0 Delivered from <sender@example.com> to <a@example.com>"
			if got := send("Subject: test\r\n\r\nhello\r\n."); got != wantDelivered {
				t.Fatalf("end of data: %q, want %q", got, wantDelivered)
			}
		})
	}

	// "<>" itself stays the null sender and reaches the backend as such.
	t.Run("null reverse-path", func(t *testing.T) {
		backend := startNestedMailBackend(t)
		conn, reader, _ := startNestedMailProxySession(t, backend.addr)
		send := func(cmd string) string {
			t.Helper()
			if _, err := io.WriteString(conn, cmd+"\r\n"); err != nil {
				t.Fatalf("writing %q: %v", cmd, err)
			}
			return readReply(t, reader)
		}

		if got := send("LHLO client.example.com"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("LHLO: %q, want 250", got)
		}
		if got := send("MAIL FROM:<>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("MAIL FROM:<>: %q, want 250", got)
		}
		if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("RCPT: %q, want 250", got)
		}
		if got := send("DATA"); !strings.HasPrefix(got, "354 ") {
			t.Fatalf("DATA: %q, want 354", got)
		}
		wantDelivered := "250 2.0.0 Delivered from <> to <a@example.com>"
		if got := send("Subject: bounce\r\n\r\nhello\r\n."); got != wantDelivered {
			t.Fatalf("end of data: %q, want %q", got, wantDelivered)
		}
	})

	// Trailing characters immediately after ">" in RCPT TO (no SP before parameters)
	// must be refused with 501 5.1.3 without reaching the backend or having the
	// trailing text stripped as an ESMTP parameter.
	t.Run("trailing text after forward-path", func(t *testing.T) {
		backend := startNestedMailBackend(t)
		conn, reader, _ := startNestedMailProxySession(t, backend.addr)
		send := func(cmd string) string {
			t.Helper()
			if _, err := io.WriteString(conn, cmd+"\r\n"); err != nil {
				t.Fatalf("writing %q: %v", cmd, err)
			}
			return readReply(t, reader)
		}

		if got := send("LHLO client.example.com"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("LHLO: %q, want 250", got)
		}
		if got := send("MAIL FROM:<sender@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("MAIL FROM: %q, want 250", got)
		}
		for _, rcpt := range []string{
			"RCPT TO:<a@example.com>@other.org",
			"RCPT TO:<a@example.com>NOTIFY=NEVER",
			`RCPT TO: "<a@example.com> NOTIFY=NEVER"`,
		} {
			want := "501 5.1.3 Bad recipient address syntax"
			if got := send(rcpt); got != want {
				t.Errorf("%s: %q, want %q", rcpt, got, want)
			}
		}
		if got := send("DATA"); !strings.HasPrefix(got, "503 5.5.1 ") {
			t.Errorf("DATA after refused RCPTs: %q, want 503 5.5.1", got)
		}
		for _, cmd := range backend.commands() {
			t.Errorf("backend was sent %q for refused RCPT", cmd)
		}
	})
}

// A reverse-path go-smtp reads, and a sora backend accepts, is not refused by the proxy
// either (#1907): a quoted local part holding a space, and the dot-strings and domains
// go-smtp is lenient about. Each reaches the backend as the client wrote it, inside its
// angle brackets. A forward-path with a quoted space stays refused: recipients are
// checked strictly.
func TestLenientReversePathForwarded(t *testing.T) {
	for _, from := range []string{
		`"john doe"@example.org`,
		`"john \"jd\" doe"@example.org`,
		"first..last@example.org",
		".lead@example.org",
		"trail.@example.org",
		"user@localhost",
	} {
		t.Run(from, func(t *testing.T) {
			backend := startNestedMailBackend(t)
			conn, reader, _ := startNestedMailProxySession(t, backend.addr)
			send := func(cmd string) string {
				t.Helper()
				if _, err := io.WriteString(conn, cmd+"\r\n"); err != nil {
					t.Fatalf("writing %q: %v", cmd, err)
				}
				return readReply(t, reader)
			}

			if got := send("LHLO client.example.com"); !strings.HasPrefix(got, "250 ") {
				t.Fatalf("LHLO: %q, want 250", got)
			}
			if got := send("MAIL FROM:<" + from + "> SIZE=10"); !strings.HasPrefix(got, "250 ") {
				t.Fatalf("MAIL FROM:<%s>: %q, want 250", from, got)
			}
			if got := send(`RCPT TO:<"john doe"@example.com>`); got != "501 5.1.3 Bad recipient address syntax" {
				t.Errorf("quoted RCPT: %q, want 501 5.1.3", got)
			}
			if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "250 ") {
				t.Fatalf("RCPT: %q, want 250", got)
			}
			cmds := backend.commands()
			if len(cmds) == 0 || !strings.HasPrefix(cmds[0], "#1 MAIL FROM:<"+from+">") {
				t.Errorf("backend commands = %q, want MAIL FROM:<%s> first", cmds, from)
			}
		})
	}
}
