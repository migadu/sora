package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/proxy"
)

// twoPoolProxy is a proxy with max_message_size 1000 over the pools "a" (the backend at
// aAddr) and "b" (bAddr): its remote lookup routes a@example.com into pool a and every
// other recipient into pool b.
func twoPoolProxy(t *testing.T, aAddr, bAddr string) *Server {
	t.Helper()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		pool := "b"
		if strings.HasPrefix(email, "a@") {
			pool = "a"
		}
		json.NewEncoder(w).Encode(map[string]any{"address": email, "pool": pool})
	}))
	t.Cleanup(lookup.Close)
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name: "held-mail", RemotePort: 24, ConnectTimeout: time.Second,
		MaxMessageSize: 1000,
		Pools: []proxy.PoolSpec{
			{Name: "a", Backends: []string{aAddr}},
			{Name: "b", Backends: []string{bAddr}},
		},
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })
	return srv
}

type clientStep struct{ cmd, want string }

// openLMTPSession runs a session of srv over a pipe, past its greeting and LHLO, and
// returns a function that sends the steps in order, each one line (a message body ending
// in "." included) answered by one reply that must start with the step's want.
func openLMTPSession(t *testing.T, srv *Server) (run func(steps ...clientStep)) {
	t.Helper()
	front, accepted := net.Pipe()
	sess := newSession(srv, accepted, nil)
	done := make(chan struct{})
	go func() { defer close(done); sess.handleConnection() }()
	t.Cleanup(func() {
		front.Close()
		<-done
	})
	front.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(front)
	if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q", greeting)
	}
	run = func(steps ...clientStep) {
		t.Helper()
		for _, step := range steps {
			if _, err := io.WriteString(front, step.cmd+"\r\n"); err != nil {
				t.Fatal(err)
			}
			if got := readReply(t, reader); !strings.HasPrefix(got, step.want) {
				t.Fatalf("%q: %q, want %q", step.cmd, got, step.want)
			}
		}
	}
	run(clientStep{"LHLO mta.example.com", "250 "})
	return run
}

// The MAIL of a transaction is answered as on a new connection, whichever backend an
// earlier transaction on the connection left held: the proxy checks the declared size
// against the limit it advertised (RFC 1870 section 6.1) and answers, and a backend is
// sent the MAIL with the first recipient that stays on it. Here the held backend A (pool
// a, fixed maximum 100) would refuse the second message's SIZE=500, with 552, on which
// "The client should then declare the message undeliverable" (section 6.2 (2)), or with
// 452, but none of its recipients route to A: B (pool b, maximum 1000) takes the message,
// as it does on a new connection, and A is never asked.
func TestHeldBackendDoesNotAnswerMAIL(t *testing.T) {
	for _, refusal := range []string{"552 5.3.4 Max message size exceeded", "452 4.3.1 Insufficient system storage"} {
		for _, end := range []string{"DATA", "RSET"} {
			t.Run(refusal[:3]+"/after "+end, func(t *testing.T) {
				aAddr, aMails := sizeBackend{name: "A", lhloSize: "SIZE 100", refuseAbove: 100, refuseReply: refusal}.start(t)
				bAddr, _ := sizeBackend{name: "B", lhloSize: "SIZE 1000", refuseAbove: 1000}.start(t)
				srv := twoPoolProxy(t, aAddr, bAddr)
				second := []clientStep{
					{"MAIL FROM:<s@example.com> SIZE=500", "250 "},
					{"RCPT TO:<b@example.com>", "250 "},
					{"DATA", "354 "},
					{"Subject: second\r\n\r\nbody\r\n.", "250 2.0.0 Delivered by B"},
				}

				// A new connection.
				openLMTPSession(t, srv)(second...)

				// A connection that holds A from the first message.
				run := openLMTPSession(t, srv)
				run(clientStep{"MAIL FROM:<s@example.com> SIZE=50", "250 "}, clientStep{"RCPT TO:<a@example.com>", "250 "})
				if end == "DATA" {
					run(clientStep{"DATA", "354 "}, clientStep{"Subject: first\r\n\r\nbody\r\n.", "250 2.0.0 Delivered by A"})
				} else {
					run(clientStep{"RSET", "250 "})
				}
				run(second...)

				if got, want := aMails(), []string{"MAIL FROM:<s@example.com> SIZE=50"}; !slices.Equal(got, want) {
					t.Errorf("A received %q, want %q (only the message it took)", got, want)
				}
			})
		}
	}
}

// DATA with no recipient accepted in the transaction is answered 503 by the proxy (RFC
// 2033 section 4.2: "when there have been no successful RCPT commands in the mail
// transaction, the DATA command MUST fail with a 503 reply code"), as on a new
// connection, never by a held backend, which may still hold an earlier transaction. Here
// the MTA sends a MAIL while a transaction is open ("MAIL ... MUST NOT be sent if a mail
// transaction is already open", RFC 5321 section 4.1.4), which the proxy takes for a new
// transaction, as it does on a new connection, while the held A still has the first
// recipient: forwarding DATA there would start the earlier message, whose end-of-data
// reply no recipient of this transaction would account for. The next recipient on A
// finds A refusing the MAIL (503) and gets a new connection to A.
func TestDATAWithoutAcceptedRecipientIsAnsweredByTheProxy(t *testing.T) {
	aAddr, aMails := sizeBackend{name: "A", lhloSize: "SIZE"}.start(t)
	bAddr, _ := sizeBackend{name: "B", lhloSize: "SIZE"}.start(t)
	run := openLMTPSession(t, twoPoolProxy(t, aAddr, bAddr))
	run(
		clientStep{"MAIL FROM:<first@example.com>", "250 "},
		clientStep{"RCPT TO:<a@example.com>", "250 "},
		clientStep{"MAIL FROM:<second@example.com>", "250 "},
		clientStep{"DATA", "503 5.5.1 "},
		clientStep{"RCPT TO:<a@example.com>", "250 "},
		clientStep{"DATA", "354 "},
		clientStep{"Subject: second\r\n\r\nbody\r\n.", "250 2.0.0 Delivered by A"},
	)
	want := []string{"MAIL FROM:<first@example.com>", "MAIL FROM:<second@example.com>", "MAIL FROM:<second@example.com>"}
	if got := aMails(); !slices.Equal(got, want) {
		t.Errorf("A received %q, want %q", got, want)
	}
}
