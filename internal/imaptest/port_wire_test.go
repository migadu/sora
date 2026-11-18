package imaptest

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestPortBinaryAppendWritesLiteral8AndExactPayload(t *testing.T) {
	local, remote := net.Pipe()
	payload := []byte("Subject: binary\r\n\r\n\x00\xff\r\n")
	c := &Client{conn: local, reader: bufio.NewReader(local), ctx: context.Background(), cfg: Config{CommandTimeout: time.Second}, Capabilities: map[string]bool{"BINARY": true}}
	done := make(chan error, 1)
	go func() {
		defer remote.Close()
		r := bufio.NewReader(remote)
		tag, command, err := wireReadCommand(r)
		if err != nil {
			done <- err
			return
		}
		want := fmt.Sprintf("APPEND \"box\" ~{%d}", len(payload))
		if command != want {
			done <- fmt.Errorf("command=%q want%q", command, want)
			return
		}
		if _, err := io.WriteString(remote, "+ send literal\r\n"); err != nil {
			done <- err
			return
		}
		data := make([]byte, len(payload)+2)
		if _, err := io.ReadFull(r, data); err != nil {
			done <- err
			return
		}
		if string(data) != string(payload)+"\r\n" {
			done <- fmt.Errorf("literal octets changed")
			return
		}
		_, err = fmt.Fprintf(remote, "%s OK appended\r\n", tag)
		done <- err
	}()
	_, err := c.AppendBinary("box", nil, "", payload)
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPortUnauthenticatedClientDoesNotSendCredentials(t *testing.T) {
	addr := wirePeer(t, func(conn net.Conn) error {
		if _, err := io.WriteString(conn, "* OK ready\r\n"); err != nil {
			return err
		}
		r := bufio.NewReader(conn)
		for _, want := range []string{"CAPABILITY", "NOOP"} {
			tag, command, err := wireReadCommand(r)
			if err != nil {
				return err
			}
			if command != want {
				return fmt.Errorf("received unexpected command instead of%s", want)
			}
			if command == "CAPABILITY" {
				if _, err := io.WriteString(conn, "* CAPABILITY IMAP4rev1 ID\r\n"); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(conn, "%s OK complete\r\n", tag); err != nil {
				return err
			}
		}
		return nil
	})
	c, err := DialUnauthenticated(context.Background(), Config{Addr: addr, TLSMode: "none", Username: "test", Password: "test-secret", CommandTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.OK("NOOP"); err != nil {
		t.Fatal(err)
	}
}
