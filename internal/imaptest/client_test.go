package imaptest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func wirePeer(t *testing.T, handle func(net.Conn) error) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		done <- handle(conn)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("wire peer: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("wire peer did not finish")
		}
	})
	return listener.Addr().String()
}

func wireReadCommand(r *bufio.Reader) (string, string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	tag, command, ok := strings.Cut(strings.TrimSuffix(line, "\r\n"), " ")
	if !ok || !strings.HasSuffix(line, "\r\n") {
		return "", "", errors.New("invalid client command framing")
	}
	return tag, command, nil
}

func wireLogin(conn net.Conn, caps, username, password string, greeting bool) (*bufio.Reader, error) {
	if greeting {
		if _, err := io.WriteString(conn, "* OK test peer\r\n"); err != nil {
			return nil, err
		}
	}
	r := bufio.NewReader(conn)
	for _, want := range []string{"CAPABILITY", "LOGIN " + Quote(username) + " " + Quote(password), "CAPABILITY"} {
		tag, command, err := wireReadCommand(r)
		if err != nil {
			return nil, err
		}
		if command != want {
			return nil, errors.New("unexpected command during client authentication")
		}
		if command == "CAPABILITY" {
			if _, err := io.WriteString(conn, "* CAPABILITY "+caps+"\r\n"); err != nil {
				return nil, err
			}
		}
		if _, err := io.WriteString(conn, tag+" OK done\r\n"); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func TestWireClientAppendAndPipeline(t *testing.T) {
	data := []byte("Subject: literal\r\n\r\n\xff exact bytes\r\n")
	addr := wirePeer(t, func(conn net.Conn) error {
		r, err := wireLogin(conn, "IMAP4rev1 LITERAL+", "user", "secret", true)
		if err != nil {
			return err
		}
		for _, nonSync := range []bool{false, true} {
			tag, command, err := wireReadCommand(r)
			if err != nil {
				return err
			}
			marker := fmt.Sprintf("{%d}", len(data))
			if nonSync {
				marker = fmt.Sprintf("{%d+}", len(data))
			}
			if command != "APPEND \"box\" (\\Seen) \"01-Jan-2020 00:00:00 +0000\" "+marker {
				return fmt.Errorf("unexpected APPEND command %q", command)
			}
			if !nonSync {
				if _, err := io.WriteString(conn, "* OK [ALERT] test alert\r\n+ go ahead\r\n"); err != nil {
					return err
				}
			}
			literal := make([]byte, len(data)+2)
			if _, err := io.ReadFull(r, literal); err != nil {
				return err
			}
			if !bytes.Equal(literal, append(append([]byte(nil), data...), '\r', '\n')) {
				return errors.New("APPEND literal bytes changed")
			}
			if _, err := io.WriteString(conn, "* 1 EXISTS\r\n"+tag+" OK [APPENDUID 8 90] appended\r\n"); err != nil {
				return err
			}
		}
		first, command, err := wireReadCommand(r)
		if err != nil || command != "NOOP" {
			return fmt.Errorf("first pipeline command %q: %w", command, err)
		}
		second, command, err := wireReadCommand(r)
		if err != nil || command != "STATUS \"box\" (MESSAGES)" {
			return fmt.Errorf("second pipeline command %q: %w", command, err)
		}
		_, err = io.WriteString(conn, "* 2 EXISTS\r\n* STATUS \"box\" (MESSAGES 2)\r\n"+second+" OK second\r\n"+first+" OK first\r\n")
		return err
	})
	client, err := Dial(context.Background(), Config{Addr: addr, Username: "user", Password: "secret", TLSMode: "none"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, nonSync := range []bool{false, true} {
		appendFn := client.Append
		if nonSync {
			appendFn = client.AppendNonSync
		}
		response, err := appendFn("box", []string{`\Seen`}, "01-Jan-2020 00:00:00 +0000", data)
		if err != nil {
			t.Fatal(err)
		}
		if exists, ok := response.Exists(); !ok || exists != 1 || len(response.Code("APPENDUID")) != 2 {
			t.Fatalf("APPEND data not retained: %#v", response)
		}
	}
	responses, err := client.Pipeline("NOOP", "STATUS \"box\" (MESSAGES)")
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 2 || responses[0].Text != "first" || responses[1].Text != "second" {
		t.Fatalf("pipeline tag association: %#v", responses)
	}
	for _, response := range responses {
		values, err := response.StatusValues("box")
		if err != nil || values["MESSAGES"] != 2 {
			t.Fatalf("pipeline group data missing: %#v %v", values, err)
		}
	}
}

func TestWireClientLogoutAndAuthenticationRedaction(t *testing.T) {
	const username = `user"\name`
	const password = `private-"\secret`
	encoded := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
	var trace bytes.Buffer
	addr := wirePeer(t, func(conn net.Conn) error {
		if _, err := io.WriteString(conn, "* OK test peer\r\n"); err != nil {
			return err
		}
		r := bufio.NewReader(conn)
		for i := 0; i < 3; i++ {
			tag, command, err := wireReadCommand(r)
			if err != nil {
				return err
			}
			if i == 1 {
				if command != "LOGIN "+Quote(username)+" "+Quote(password) {
					return errors.New("LOGIN did not escape credentials")
				}
				_, err = io.WriteString(conn, "* OK echoed "+password+" "+encoded+"\r\n"+tag+" OK "+password+"\r\n")
			} else {
				_, err = io.WriteString(conn, "* CAPABILITY IMAP4rev1\r\n"+tag+" OK done\r\n")
			}
			if err != nil {
				return err
			}
		}
		tag, command, err := wireReadCommand(r)
		if err != nil || command != "LOGOUT" {
			return errors.New("expected LOGOUT")
		}
		_, err = io.WriteString(conn, "* BYE closing\r\n"+tag+" OK logout completed\r\n")
		return err
	})
	client, err := Dial(context.Background(), Config{Addr: addr, Username: username, Password: password, TLSMode: "none", Trace: &trace})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.OK("LOGOUT")
	if err != nil || len(response.Data("BYE")) != 1 {
		t.Fatalf("LOGOUT with BYE: %#v %v", response, err)
	}
	for _, secret := range []string{password, Quote(password), encoded, "LOGIN"} {
		if strings.Contains(trace.String(), secret) {
			t.Fatalf("authentication leaked into trace: %q", trace.String())
		}
	}
	if !strings.Contains(trace.String(), "LOGOUT") {
		t.Fatal("non-authentication trace missing")
	}
}

func TestWireClientRejectedAuthenticationDoesNotExposeCredentials(t *testing.T) {
	const password = "keep-this-private"
	addr := wirePeer(t, func(conn net.Conn) error {
		_, _ = io.WriteString(conn, "* OK ready\r\n")
		r := bufio.NewReader(conn)
		tag, _, err := wireReadCommand(r)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(conn, "* CAPABILITY IMAP4rev1\r\n"+tag+" OK caps\r\n")
		tag, _, err = wireReadCommand(r)
		if err != nil {
			return err
		}
		_, err = io.WriteString(conn, tag+" NO you sent "+password+"\r\n")
		return err
	})
	var trace bytes.Buffer
	_, err := Dial(context.Background(), Config{Addr: addr, Username: "user", Password: password, TLSMode: "none", Trace: &trace})
	if err == nil || strings.Contains(err.Error(), password) || strings.Contains(trace.String(), password) {
		t.Fatalf("unsafe authentication failure: %v trace=%q", err, trace.String())
	}
}

func TestWireTraceOmitsNestedLiteralsAndEscapedPasswords(t *testing.T) {
	const password = `private-"\secret`
	const literal = "\x00\xffmessage text that belongs only in a literal\r\n"
	addr := wirePeer(t, func(conn net.Conn) error {
		r, err := wireLogin(conn, "IMAP4rev1", "user", password, true)
		if err != nil {
			return err
		}
		tag, _, err := wireReadCommand(r)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(conn, "* 1 FETCH (BODY[] {%d}\r\n%s)\r\n%s OK echo %s\r\n", len(literal), literal, tag, Quote(password))
		return err
	})
	var trace bytes.Buffer
	client, err := Dial(context.Background(), Config{Addr: addr, Username: "user", Password: password, TLSMode: "none", Trace: &trace})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.OK("FETCH 1 BODY.PEEK[]")
	if err != nil {
		t.Fatal(err)
	}
	fetches, err := response.Fetches()
	if err != nil || len(fetches) != 1 || fetches[0].Attrs["BODY[]"].Text != literal {
		t.Fatalf("trace redaction changed actual body: %#v %v", fetches, err)
	}
	for _, secret := range []string{password, Quote(password), literal, "message text that belongs only"} {
		if strings.Contains(trace.String(), secret) || strings.Contains(response.Text, secret) {
			t.Fatalf("sensitive data retained: trace=%q text=%q", trace.String(), response.Text)
		}
	}
	if !strings.Contains(trace.String(), fmt.Sprintf("<%d literal bytes>", len(literal))) {
		t.Fatalf("missing literal length in trace: %q", trace.String())
	}
}

func TestWireClientCancellationInterruptsRead(t *testing.T) {
	started := make(chan struct{})
	addr := wirePeer(t, func(conn net.Conn) error {
		r, err := wireLogin(conn, "IMAP4rev1", "user", "secret", true)
		if err != nil {
			return err
		}
		if _, _, err := wireReadCommand(r); err != nil {
			return err
		}
		close(started)
		_, err = r.ReadByte()
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("expected client cancellation to close connection: %w", err)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := Dial(ctx, Config{Addr: addr, Username: "user", Password: "secret", TLSMode: "none", CommandTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan error, 1)
	go func() { _, err := client.Command("NOOP"); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation left a blocked read")
	}
}

func wireCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	return cert, certPEM
}

func TestWireClientTLSModes(t *testing.T) {
	certificate, ca := wireCertificate(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"implicit", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			addr := wirePeer(t, func(raw net.Conn) error {
				if mode == "starttls" {
					if _, err := io.WriteString(raw, "* OK ready\r\n"); err != nil {
						return err
					}
					r := bufio.NewReader(raw)
					tag, command, err := wireReadCommand(r)
					if err != nil || command != "CAPABILITY" {
						return errors.New("expected pre-TLS CAPABILITY")
					}
					_, _ = io.WriteString(raw, "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n"+tag+" OK caps\r\n")
					tag, command, err = wireReadCommand(r)
					if err != nil || command != "STARTTLS" {
						return errors.New("expected STARTTLS")
					}
					if _, err := io.WriteString(raw, tag+" OK begin TLS\r\n"); err != nil {
						return err
					}
				}
				secured := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if err := secured.Handshake(); err != nil {
					return err
				}
				r, err := wireLogin(secured, "IMAP4rev1 UIDPLUS", "user", "secret", mode == "implicit")
				if err != nil {
					return err
				}
				tag, command, err := wireReadCommand(r)
				if err != nil || command != "NOOP" {
					return errors.New("expected encrypted NOOP")
				}
				_, err = io.WriteString(secured, tag+" OK encrypted\r\n")
				return err
			})
			client, err := Dial(context.Background(), Config{Addr: addr, Username: "user", Password: "secret", TLSMode: mode, CAFile: caFile})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if !client.Capabilities["UIDPLUS"] || client.Capabilities["LOGINDISABLED"] || client.Capabilities["STARTTLS"] {
				t.Fatalf("capabilities not refreshed after TLS/auth: %#v", client.Capabilities)
			}
			if _, err := client.OK("NOOP"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
