package testutils

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"regexp"
	"sync"
	"testing"
)

// SQLRecordingProxy forwards PostgreSQL connections to a real server and records the
// SQL text of every simple Query and every Parse the clients send, so a test can see
// exactly which statements a code path issues, also through database/sql and
// third-party libraries.
type SQLRecordingProxy struct {
	Host string // 127.0.0.1
	Port int

	mu         sync.Mutex
	statements []string
}

// StartSQLRecordingProxy starts a proxy to target (host:port) for the duration of t.
func StartSQLRecordingProxy(t *testing.T, target string) *SQLRecordingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("recording proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().(*net.TCPAddr)
	p := &SQLRecordingProxy{Host: addr.IP.String(), Port: addr.Port}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go p.forward(client, target)
		}
	}()
	return p
}

// Statements returns the SQL recorded so far, in order.
func (p *SQLRecordingProxy) Statements() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.statements...)
}

// sessionAdvisoryLockCall matches the SESSION-level advisory lock functions
// (pg_advisory_lock, pg_try_advisory_lock, pg_advisory_unlock, their _shared forms and
// pg_advisory_unlock_all), not the transaction-scoped pg_*advisory_xact_lock ones.
var sessionAdvisoryLockCall = regexp.MustCompile(`(?i)\bpg_(try_)?advisory_(lock|unlock)(_shared|_all)?\s*\(`)

// SessionAdvisoryLockStatements returns the recorded statements that call a
// session-level advisory lock function.
func (p *SQLRecordingProxy) SessionAdvisoryLockStatements() []string {
	var found []string
	for _, s := range p.Statements() {
		if sessionAdvisoryLockCall.MatchString(s) {
			found = append(found, s)
		}
	}
	return found
}

func (p *SQLRecordingProxy) record(sql string) {
	p.mu.Lock()
	p.statements = append(p.statements, sql)
	p.mu.Unlock()
}

func (p *SQLRecordingProxy) forward(client net.Conn, target string) {
	defer client.Close()
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer server.Close()
	go func() {
		_, _ = io.Copy(client, server)
		client.Close()
	}()

	r := bufio.NewReader(client)
	startup := true
	for {
		var header []byte
		if startup {
			header = make([]byte, 4) // untyped: length only
		} else {
			header = make([]byte, 5) // type byte and length
		}
		if _, err := io.ReadFull(r, header); err != nil {
			return
		}
		length := binary.BigEndian.Uint32(header[len(header)-4:])
		if length < 4 || length > 1<<30 {
			return
		}
		body := make([]byte, length-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		if _, err := server.Write(append(header, body...)); err != nil {
			return
		}

		if startup {
			// An SSL or GSSAPI encryption request is answered with one byte and followed
			// by the real startup message; anything else is the startup message.
			if len(body) >= 4 {
				code := binary.BigEndian.Uint32(body[:4])
				if code == 80877103 || code == 80877104 {
					continue
				}
			}
			startup = false
			continue
		}
		switch header[0] {
		case 'Q': // Query: the SQL text, NUL-terminated
			p.record(string(bytes.TrimRight(body, "\x00")))
		case 'P': // Parse: statement name, then the SQL text, each NUL-terminated
			if i := bytes.IndexByte(body, 0); i >= 0 {
				rest := body[i+1:]
				if j := bytes.IndexByte(rest, 0); j >= 0 {
					p.record(string(rest[:j]))
				}
			}
		}
	}
}
