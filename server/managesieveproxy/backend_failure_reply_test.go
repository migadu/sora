package managesieveproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// Temporary failures are coded TRYLATER, RFC 5804 section 1.3: "A command failed due
// to a temporary server failure. The client MAY continue using local information and
// try the command later." UNAVAILABLE is the IMAP code of RFC 5530, which ManageSieve
// does not define, so a ManageSieve client cannot tell it from any other NO.

// TestManageSieveProxyBackendFailureIsTryLater: once the client's credentials are
// accepted, a backend the proxy cannot reach or log in to is a temporary failure.
func TestManageSieveProxyBackendFailureIsTryLater(t *testing.T) {
	const want = `NO (TRYLATER) "Backend server temporarily unavailable"`
	for _, tc := range []struct {
		name    string
		backend func(t *testing.T) string
	}{
		{"backend down", deadSieveBackendAddr},
		{"backend refuses the proxy login", refusingSieveBackend},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startSieveProxy(t, context.Background(), tc.backend(t), acceptingSieveLookup(t))
			if got := authenticateViaSieveProxy(t, addr); got != want {
				t.Errorf("AUTHENTICATE with a failing backend: %q, want %q", got, want)
			}
		})
	}
}

// TestManageSieveProxyShutdownDuringAuthIsTryLater: a login cut short by the server
// shutting down is a temporary failure, not a wrong password.
func TestManageSieveProxyShutdownDuringAuthIsTryLater(t *testing.T) {
	const want = `NO (TRYLATER) "Service temporarily unavailable, please try again later"`
	lookupStarted := make(chan struct{}, 1)
	lookup := func(w http.ResponseWriter, r *http.Request) {
		lookupStarted <- struct{}{}
		select { // held until the proxy gives up on it
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}
	appCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	addr := startSieveProxy(t, appCtx, deadSieveBackendAddr(t), lookup)

	reply := make(chan string, 1)
	go func() { reply <- authenticateViaSieveProxy(t, addr) }()
	select {
	case <-lookupStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy did not ask the remote lookup")
	}
	shutdown()
	if got := <-reply; got != want {
		t.Errorf("AUTHENTICATE cut short by shutdown: %q, want %q", got, want)
	}
}

// deadSieveBackendAddr returns an address nothing listens on.
func deadSieveBackendAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// refusingSieveBackend serves ManageSieve connections that greet and then answer
// every command NO, so the proxy's master SASL login is rejected.
func refusingSieveBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				io.WriteString(conn, fakeSieveCapabilities)
				r := bufio.NewReader(conn)
				for {
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
					io.WriteString(conn, "NO \"Authentication failed\"\r\n")
				}
			}()
		}
	}()
	return ln.Addr().String()
}

const sieveTestUser, sieveTestPassword = "user@example.com", "secret"

// acceptingSieveLookup is a remote lookup that accepts sieveTestUser's password and
// leaves the choice of backend to the proxy.
func acceptingSieveLookup(t *testing.T) http.HandlerFunc {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(sieveTestPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"address": r.URL.Query().Get("email"), "password_hash": string(hash)})
	}
}

// startSieveProxy starts a proxy under appCtx whose only backend is backendAddr and
// whose remote lookup is served by lookup, and returns its address.
func startSieveProxy(t *testing.T, appCtx context.Context, backendAddr string, lookup http.HandlerFunc) string {
	t.Helper()
	lookupSrv := httptest.NewServer(lookup)
	t.Cleanup(lookupSrv.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv, err := New(appCtx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name:               "backend-failure",
		Addr:               addr,
		RemoteAddrs:        []string{backendAddr},
		ConnectTimeout:     2 * time.Second,
		InsecureAuth:       true,
		MasterSASLUsername: "proxy-master",
		MasterSASLPassword: "proxy-master-secret",
		RemoteLookup:       &config.RemoteLookupConfig{Enabled: true, URL: lookupSrv.URL + "/lookup?email=$email", Timeout: "5s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { srv.Stop() })
	return addr
}

// authenticateViaSieveProxy logs sieveTestUser in through the proxy at addr and
// returns the reply to AUTHENTICATE.
func authenticateViaSieveProxy(t *testing.T, addr string) string {
	var conn net.Conn
	var err error
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return "dial proxy: " + err.Error()
		}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	readReply := func() string {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return "read: " + err.Error()
			}
			if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
				return strings.TrimRight(line, "\r\n")
			}
		}
	}
	if greeting := readReply(); !strings.HasPrefix(greeting, "OK") {
		return "greeting: " + greeting
	}
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + sieveTestUser + "\x00" + sieveTestPassword))
	io.WriteString(conn, `AUTHENTICATE "PLAIN" "`+plain+"\"\r\n")
	return readReply()
}
