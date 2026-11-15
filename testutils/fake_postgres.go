package testutils

import (
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// PostgresLogin is what a client sent to FakePostgres: the startup parameters and
// the cleartext password it answered the authentication request with.
type PostgresLogin struct {
	User     string
	Password string
	Database string
}

// FakePostgres listens on 127.0.0.1, asks every client for a cleartext password,
// records the login and then refuses it. It shows exactly which credentials a
// connection string resolves to, without a real server. The listener closes with
// the test.
type FakePostgres struct {
	Addr   string // 127.0.0.1:port
	Host   string // 127.0.0.1
	Port   int
	logins chan PostgresLogin
}

// StartFakePostgres starts a FakePostgres for the duration of t.
func StartFakePostgres(t *testing.T) *FakePostgres {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake postgres listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	fp := &FakePostgres{
		Addr:   addr.String(),
		Host:   addr.IP.String(),
		Port:   addr.Port,
		logins: make(chan PostgresLogin, 64),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fp.serve(conn)
		}
	}()
	return fp
}

func (fp *FakePostgres) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	backend := pgproto3.NewBackend(conn, conn)

	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := msg.(*pgproto3.SSLRequest); ok {
		if _, err := conn.Write([]byte("N")); err != nil {
			return
		}
		if msg, err = backend.ReceiveStartupMessage(); err != nil {
			return
		}
	}
	startup, ok := msg.(*pgproto3.StartupMessage)
	if !ok {
		return
	}

	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		return
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return
	}
	msg, err = backend.Receive()
	if err != nil {
		return
	}
	password, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		return
	}

	select {
	case fp.logins <- PostgresLogin{
		User:     startup.Parameters["user"],
		Password: password.Password,
		Database: startup.Parameters["database"],
	}:
	default:
	}

	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "fake postgres refuses every login"})
	_ = backend.Flush()
}

// NextLogin returns the next login the server received, or fails the test if none
// arrives within a few seconds. cause is reported with the failure, typically the
// connect error, which tells why the client never reached the server.
func (fp *FakePostgres) NextLogin(t *testing.T, cause error) PostgresLogin {
	t.Helper()
	select {
	case login := <-fp.logins:
		return login
	case <-time.After(2 * time.Second):
		t.Fatalf("no login reached the fake server at %s; client error: %v", fp.Addr, cause)
		return PostgresLogin{}
	}
}
