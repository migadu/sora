package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
)

// startSizeDeclarationSession runs a session of a plain-text proxy whose max_message_size is
// maxSize over a pipe and returns the client end with the greeting read.
func startSizeDeclarationSession(t *testing.T, maxSize int64) (net.Conn, *bufio.Reader) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}
	srv.settings.Store(&reloadableSettings{maxMessageSize: maxSize})

	serverEnd, client := net.Pipe()
	sess := newSession(srv, server.NewSoraConn(serverEnd, server.SoraConnConfig{Protocol: "lmtp_proxy"}), nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleConnection()
	}()
	t.Cleanup(func() {
		client.Close()
		<-done
	})

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	if line := readReply(t, reader); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("greeting = %q", line)
	}
	return client, reader
}

// The proxy advertises its max_message_size as "SIZE <n>" in LHLO. RFC 1870 section 6.1:
// "If the indicated size is larger than the server's fixed maximum message size, the
// server responds with code 552", and section 7 has a server with a fixed limit "return
// a 552 reply code if the client's declared size exceeds its fixed size limit". The
// refusal comes before RCPT, so the MTA never sends the body. A declaration at or under
// the limit, or with no SIZE, is accepted.
func TestMAILRefusesDeclaredSizeOverTheAdvertisedLimit(t *testing.T) {
	conn, r := startSizeDeclarationSession(t, 1024)
	io.WriteString(conn, "LHLO client.example.org\r\n")
	var lhlo []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading LHLO reply: %v", err)
		}
		lhlo = append(lhlo, strings.TrimRight(line, "\r\n"))
		if len(line) < 4 || line[3] != '-' {
			break
		}
	}
	if !strings.Contains(strings.Join(lhlo, "\n"), "250-SIZE 1024") {
		t.Fatalf("LHLO reply %q does not advertise SIZE 1024", lhlo)
	}

	tests := []struct {
		mail, want string
	}{
		{"MAIL FROM:<a@example.org> SIZE=1025", "552 5.3.4 "},
		{"MAIL FROM:<a@example.org> BODY=8BITMIME size=104857600", "552 5.3.4 "},
		{"MAIL FROM:<> SIZE=99999999999999999999", "552 5.3.4 "},
		{"MAIL FROM:<a@example.org> SIZE=1024", "250 "},
		{"MAIL FROM:<a@example.org> SIZE=00000000000000001024", "250 "},
		{"MAIL FROM:<a@example.org>", "250 "},
	}
	for _, tt := range tests {
		io.WriteString(conn, tt.mail+"\r\n")
		if got := readReply(t, r); !strings.HasPrefix(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.mail, got, tt.want)
		}
		io.WriteString(conn, "RSET\r\n")
		readReply(t, r)
	}

	// A refused MAIL starts no transaction: RCPT has no sender to go with.
	io.WriteString(conn, fmt.Sprintf("MAIL FROM:<a@example.org> SIZE=%d\r\n", 2048))
	if got := readReply(t, r); !strings.HasPrefix(got, "552 ") {
		t.Fatalf("MAIL SIZE=2048 over a limit of 1024: %q, want 552", got)
	}
	io.WriteString(conn, "RCPT TO:<user@example.com>\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "503 ") {
		t.Errorf("RCPT after a MAIL refused for its size: %q, want 503", got)
	}
}

// A SIZE value is "size-value ::= 1*20DIGIT" (RFC 1870 section 3 (4)), and "Only one SIZE
// parameter may be specified in a single MAIL command" (section 6). Anything else is a
// syntax error in the parameters: 501 5.5.4, as the backend (go-smtp) answers it, and no
// transaction starts.
func TestMAILRefusesMalformedSizeParameter(t *testing.T) {
	conn, r := startSizeDeclarationSession(t, 1024)
	io.WriteString(conn, "LHLO client.example.org\r\n")
	readReply(t, r)
	for _, mail := range []string{
		"MAIL FROM:<a@example.org> SIZE=12x",
		"MAIL FROM:<a@example.org> SIZE=",
		"MAIL FROM:<a@example.org> SIZE",
		"MAIL FROM:<a@example.org> SIZE=-1",
		"MAIL FROM:<a@example.org> SIZE=+1",
		"MAIL FROM:<a@example.org> SIZE=1.5",
		"MAIL FROM:<a@example.org> SIZE=0x10",
		"MAIL FROM:<a@example.org> SIZE=000000000000000000001",    // 21 digits
		"MAIL FROM:<a@example.org> SIZE=99999999999999999999999x", // overflows before the x
		"MAIL FROM:<a@example.org> SIZE=100 SIZE=100",
	} {
		io.WriteString(conn, mail+"\r\n")
		if got := readReply(t, r); !strings.HasPrefix(got, "501 5.5.4 ") {
			t.Errorf("%s: %q, want 501 5.5.4", mail, got)
			io.WriteString(conn, "RSET\r\n") // this session has no backend to take a RCPT
			readReply(t, r)
			continue
		}
		io.WriteString(conn, "RCPT TO:<user@example.com>\r\n")
		if got := readReply(t, r); !strings.HasPrefix(got, "503 ") {
			t.Errorf("RCPT after %s: %q, want 503", mail, got)
		}
	}
}

// With no limit (max_message_size = 0) the proxy advertises no SIZE and refuses no
// declaration.
func TestMAILWithoutLimitAcceptsAnyDeclaredSize(t *testing.T) {
	conn, r := startSizeDeclarationSession(t, 0)
	io.WriteString(conn, "LHLO client.example.org\r\n")
	readReply(t, r)
	io.WriteString(conn, "MAIL FROM:<a@example.org> SIZE=104857600\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "250 ") {
		t.Errorf("MAIL with SIZE and no limit: %q, want 250", got)
	}
}

// sizeBackend is a scripted LMTP backend for the SIZE forwarding tests. It advertises
// lhloSize in its LHLO reply ("" advertises no SIZE) and, as a go-smtp backend does,
// refuses a MAIL whose SIZE is above refuseAbove with 552 (0: refuses none). It serves
// any number of connections and records every MAIL command it receives.
type sizeBackend struct {
	lhloSize    string
	refuseAbove int64
}

func (b sizeBackend) start(t *testing.T) (addr string, mails func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []string
	serve := func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "220 backend ready\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			verb, _, _ := strings.Cut(line, " ")
			switch strings.ToUpper(verb) {
			case "LHLO":
				if b.lhloSize != "" {
					io.WriteString(conn, "250-backend\r\n250-"+b.lhloSize+"\r\n250 PIPELINING\r\n")
				} else {
					io.WriteString(conn, "250-backend\r\n250 PIPELINING\r\n")
				}
			case "MAIL":
				mu.Lock()
				got = append(got, line)
				mu.Unlock()
				refused := false
				for _, arg := range strings.Fields(line) {
					if v, ok := strings.CutPrefix(strings.ToUpper(arg), "SIZE="); ok {
						n, err := strconv.ParseInt(v, 10, 64)
						refused = b.refuseAbove > 0 && (err != nil || n > b.refuseAbove)
					}
				}
				if refused {
					io.WriteString(conn, "552 5.3.4 Max message size exceeded\r\n")
				} else {
					io.WriteString(conn, "250 2.0.0 Roger\r\n")
				}
			case "QUIT":
				io.WriteString(conn, "221 bye\r\n")
				return
			default:
				io.WriteString(conn, "250 2.0.0 OK\r\n")
			}
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// startSizeForwardingSession runs a session of a proxy with the default max_message_size
// (50 MiB) in front of the backend at backendAddr, every recipient routed there by remote
// lookup, and returns the client end after LHLO.
func startSizeForwardingSession(t *testing.T, backendAddr string) (send func(string) string) {
	t.Helper()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
	}))
	t.Cleanup(lookup.Close)
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name: "size", RemoteAddrs: []string{backendAddr}, RemotePort: 24, ConnectTimeout: time.Second,
		MaxMessageSize: 52428800,
		RemoteLookup:   &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

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
	send = func(line string) string {
		t.Helper()
		if _, err := io.WriteString(front, line+"\r\n"); err != nil {
			t.Fatal(err)
		}
		return readReply(t, reader)
	}
	if reply := send("LHLO client.example.org"); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("LHLO = %q", reply)
	}
	return send
}

// The MTA's SIZE declaration reaches the backend, so a backend whose fixed maximum is
// lower than the proxy's can refuse it before the body is sent, but only a backend that
// advertised SIZE: "When supported by the server, a client may use the extended MAIL
// command" (RFC 1870 section 4), and "If service extensions were negotiated, the MAIL
// command may also carry parameters associated with a particular service extension"
// (RFC 5321 section 4.1.1.2). It goes with
// the MAIL sent when the backend is connected for the first recipient and with the MAIL
// relayed to a backend held from an earlier transaction, and a MAIL without SIZE leaves
// none behind.
func TestMAILForwardsDeclaredSizeToBackendThatAdvertisesSIZE(t *testing.T) {
	for _, tt := range []struct {
		name, lhloSize string
		forwarded      bool
	}{
		{"SIZE with a limit", "SIZE 52428800", true},
		{"SIZE without a limit", "SIZE", true},
		{"no SIZE", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			addr, mails := sizeBackend{lhloSize: tt.lhloSize}.start(t)
			send := startSizeForwardingSession(t, addr)
			for _, step := range []struct{ cmd, want string }{
				{"MAIL FROM:<a@example.org> SIZE=1000", "250 "},
				{"RCPT TO:<user@example.com>", "250 "},
				{"RSET", "250 "},
				{"MAIL FROM:<b@example.org> size=2000", "250 "},
				{"RSET", "250 "},
				{"MAIL FROM:<c@example.org>", "250 "},
			} {
				if got := send(step.cmd); !strings.HasPrefix(got, step.want) {
					t.Fatalf("%s: %q, want %q", step.cmd, got, step.want)
				}
			}
			want := []string{"MAIL FROM:<a@example.org>", "MAIL FROM:<b@example.org>", "MAIL FROM:<c@example.org>"}
			if tt.forwarded {
				want[0] += " SIZE=1000"
				want[1] += " SIZE=2000"
			}
			if got := mails(); !slices.Equal(got, want) {
				t.Errorf("backend received %q, want %q", got, want)
			}
		})
	}
}

// A backend whose fixed maximum is below the declared size refuses the forwarded MAIL with
// 552. That is a permanent refusal for the MTA too: RFC 1870 section 6.4 lets a server
// "return a 452 or 552 reply code in response to a RCPT command, based on its
// unwillingness to accept a message of the declared size", and "If a 552 code is
// returned, the client may not requeue the message". When the backend is connected for a
// recipient, each recipient is answered 552, never "451 Backend connection failed", which
// would have the MTA retry the message until it expires. A backend held from an earlier
// transaction answers the MAIL itself.
func TestBackendRefusalOfDeclaredSizeIsPermanent(t *testing.T) {
	addr, _ := sizeBackend{lhloSize: "SIZE 1024", refuseAbove: 1024}.start(t)
	send := startSizeForwardingSession(t, addr)
	for _, step := range []struct{ cmd, want string }{
		// The proxy's own limit is 50 MiB: it accepts the MAIL and connects at RCPT.
		{"MAIL FROM:<a@example.org> SIZE=2000", "250 "},
		{"RCPT TO:<user@example.com>", "552 5.3.4 "},
		{"RCPT TO:<other@example.com>", "552 5.3.4 "},
		{"RSET", "250 "},
		// Within the backend's limit: connected and held.
		{"MAIL FROM:<a@example.org> SIZE=1000", "250 "},
		{"RCPT TO:<user@example.com>", "250 "},
		{"RSET", "250 "},
		{"MAIL FROM:<a@example.org> SIZE=2000", "552 5.3.4 "},
		{"RCPT TO:<user@example.com>", "503 "},
	} {
		if got := send(step.cmd); !strings.HasPrefix(got, step.want) {
			t.Errorf("%s: %q, want %q", step.cmd, got, step.want)
		}
	}
}

func TestIsSIZECapability(t *testing.T) {
	for _, tt := range []struct {
		line string
		want bool
	}{
		{"250-SIZE 52428800\r\n", true},
		{"250 SIZE\r\n", true},
		{"250-size 1024", true},
		{"250-SIZEX 1024", false},
		{"250-SMTPUTF8", false},
		{"250", false},
		{"", false},
	} {
		if got := isSIZECapability(tt.line); got != tt.want {
			t.Errorf("isSIZECapability(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}
