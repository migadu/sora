package imap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// wireCapSession wraps a real *meteredSession so a database-free wire test can
// log in and select an empty mailbox while exercising the exact session
// interfaces, capability sets and command handlers production connections use.
type wireCapSession struct {
	*meteredSession
}

func (s *wireCapSession) Login(_ context.Context, username, _ string) error {
	addr, err := serverPkg.NewAddress(username)
	if err != nil {
		addr, _ = serverPkg.NewAddress("user@example.com")
	}
	s.IMAPUser = NewIMAPUser(addr, 1)
	s.Session.User = &s.IMAPUser.User
	return nil
}

func (s *wireCapSession) Select(_ context.Context, mboxName string, _ *imap.SelectOptions) (*imap.SelectData, error) {
	return &imap.SelectData{
		List:          &imap.ListData{Delim: '/', Mailbox: mboxName},
		UIDValidity:   1,
		UIDNext:       1,
		HighestModSeq: 1,
	}, nil
}

type wireCapClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	tag  int
	sess *IMAPSession
}

func dialWireCapServer(t *testing.T, opts IMAPServerOptions) *wireCapClient {
	t.Helper()
	srv := newDisabledCapsTestServer(t, opts)
	sessions := make(chan *IMAPSession, 1)
	is := imapserver.New(&imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			sess, greeting, err := srv.newSession(c)
			if err != nil {
				return nil, nil, err
			}
			ms := sess.(*meteredSession)
			sessions <- ms.IMAPSession
			return &wireCapSession{meteredSession: ms}, greeting, nil
		},
		Logger:       log.New(io.Discard, "", 0),
		InsecureAuth: true,
		Caps:         srv.caps,
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go is.Serve(ln)
	t.Cleanup(func() { is.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}

	var imapSess *IMAPSession
	select {
	case imapSess = <-sessions:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for session")
	}

	c := &wireCapClient{t: t, conn: conn, br: br, sess: imapSess}
	c.mustOK("LOGIN user@example.com secret")
	return c
}

func (c *wireCapClient) sendCmd(cmd string) (resp, tagged string, err error) {
	c.t.Helper()
	c.tag++
	tag := fmt.Sprintf("t%d", c.tag)
	if _, err := fmt.Fprintf(c.conn, "%s %s\r\n", tag, cmd); err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	for {
		line, err := c.br.ReadString('\n')
		buf.WriteString(line)
		if strings.HasPrefix(line, tag+" ") {
			return buf.String(), line, nil
		}
		if err != nil {
			return buf.String(), "", err
		}
	}
}

func (c *wireCapClient) mustOK(cmd string) string {
	c.t.Helper()
	resp, tagged, err := c.sendCmd(cmd)
	if err != nil {
		c.t.Fatalf("%s failed with I/O error %v; partial response:\n%s", cmd, err, resp)
	}
	if !strings.Contains(tagged, " OK ") {
		c.t.Fatalf("%s: want OK, got:\n%s", cmd, resp)
	}
	return resp
}

func (c *wireCapClient) mustBad(cmd string) {
	c.t.Helper()
	resp, tagged, err := c.sendCmd(cmd)
	if err != nil {
		c.t.Fatalf("%s failed with I/O error %v; partial response:\n%s", cmd, err, resp)
	}
	if !strings.Contains(tagged, " BAD ") {
		c.t.Fatalf("%s: want BAD, got:\n%s", cmd, resp)
	}
}

func parseWireCaps(t *testing.T, resp string) []string {
	t.Helper()
	for _, line := range strings.Split(resp, "\r\n") {
		if rest, ok := strings.CutPrefix(line, "* CAPABILITY "); ok {
			return strings.Fields(rest)
		}
	}
	t.Fatalf("no untagged CAPABILITY line in:\n%s", resp)
	return nil
}

// When a client enables IMAP4rev2 (or CONDSTORE) and later matches a
// client_filters rule that disables ESEARCH (or CONDSTORE), the enabled
// capability cannot be withdrawn on this connection (RFC 9051 §6.3.1, RFC 7162
// §3.1). Because ESEARCH remains active through IMAP4rev2, extensions that
// require ESEARCH (ESORT, MULTISEARCH) and were not named in disable_caps must
// not be deleted by a cascade that assumed ESEARCH was gone; likewise QRESYNC
// must stay offered when CONDSTORE remains enabled and QRESYNC itself was not
// disabled. Extensions explicitly named in disable_caps and not enabled on the
// connection are still withdrawn.
func TestClientFilter_AfterEnableDoesNotCascadeFromKeptCapabilities(t *testing.T) {
	t.Run("ESEARCH filter after ENABLE IMAP4rev2 keeps ESORT and MULTISEARCH", func(t *testing.T) {
		c := dialWireCapServer(t, IMAPServerOptions{
			CapabilityFilters: []config.ClientCapabilityFilter{{
				ClientName:  "^buggy$",
				DisableCaps: []string{"ESEARCH"},
			}},
		})
		if resp := c.mustOK("ENABLE IMAP4rev2"); !strings.Contains(resp, "* ENABLED IMAP4rev2\r\n") {
			t.Fatalf("ENABLE IMAP4rev2: got:\n%s", resp)
		}
		c.mustOK(`ID ("name" "buggy")`)

		caps := parseWireCaps(t, c.mustOK("CAPABILITY"))
		for _, want := range []string{"IMAP4rev2", "ESORT", "MULTISEARCH"} {
			if !slices.Contains(caps, want) {
				t.Errorf("CAPABILITY after ENABLE IMAP4rev2 and ESEARCH filter lost %s: %v", want, caps)
			}
		}

		c.mustOK("SELECT INBOX")
		if resp := c.mustOK("SORT RETURN (MIN) (DATE) UTF-8 1"); !strings.Contains(resp, "* ESEARCH ") {
			t.Errorf("SORT RETURN (MIN) after ENABLE IMAP4rev2 and ESEARCH filter: want ESEARCH, got:\n%s", resp)
		}
		err := callHandler(func() error {
			_, err := c.sess.MultiSearch(context.Background(), &imap.SearchSource{Personal: true}, &imap.SearchCriteria{}, &imap.SearchOptions{ReturnAll: true})
			return err
		})
		if isBad(err) {
			t.Errorf("MULTISEARCH after ENABLE IMAP4rev2 and ESEARCH filter was refused with BAD: %v", err)
		}
	})

	t.Run("explicit ESORT in filter is still withdrawn after ENABLE IMAP4rev2", func(t *testing.T) {
		c := dialWireCapServer(t, IMAPServerOptions{
			CapabilityFilters: []config.ClientCapabilityFilter{{
				ClientName:  "^buggy$",
				DisableCaps: []string{"ESEARCH", "ESORT"},
			}},
		})
		c.mustOK("ENABLE IMAP4rev2")
		c.mustOK(`ID ("name" "buggy")`)

		caps := parseWireCaps(t, c.mustOK("CAPABILITY"))
		for _, want := range []string{"IMAP4rev2", "MULTISEARCH"} {
			if !slices.Contains(caps, want) {
				t.Errorf("CAPABILITY lost %s: %v", want, caps)
			}
		}
		if slices.Contains(caps, "ESORT") {
			t.Errorf("CAPABILITY still advertises explicitly disabled ESORT: %v", caps)
		}
		c.mustOK("SELECT INBOX")
		c.mustBad("SORT RETURN (MIN) (DATE) UTF-8 1")
	})

	t.Run("CONDSTORE filter after ENABLE CONDSTORE keeps QRESYNC", func(t *testing.T) {
		c := dialWireCapServer(t, IMAPServerOptions{
			CapabilityFilters: []config.ClientCapabilityFilter{{
				ClientName:  "^buggy$",
				DisableCaps: []string{"CONDSTORE"},
			}},
		})
		if resp := c.mustOK("ENABLE CONDSTORE"); !strings.Contains(resp, "* ENABLED CONDSTORE\r\n") {
			t.Fatalf("ENABLE CONDSTORE: got:\n%s", resp)
		}
		c.mustOK(`ID ("name" "buggy")`)

		caps := parseWireCaps(t, c.mustOK("CAPABILITY"))
		for _, want := range []string{"CONDSTORE", "QRESYNC"} {
			if !slices.Contains(caps, want) {
				t.Errorf("CAPABILITY after ENABLE CONDSTORE and CONDSTORE filter lost %s: %v", want, caps)
			}
		}
	})
}

// go-imap decides whether a connection speaks IMAP4rev2 from the server-global
// capability set (conn.isIMAP4rev2), while availableCaps reads the session's
// capability set. Allowing client_filters to remove IMAP4rev1 on a server that
// offers IMAP4rev1 either leaves the session with neither base version (panicking
// availableCaps when IMAP4rev2 is also gone) or advertises IMAP4rev2 alone
// without ENABLE while serving IMAP4rev1 responses.
func TestClientFilter_CannotDisableIMAP4rev1(t *testing.T) {
	t.Run("warns at startup and keeps IMAP4rev1 when IMAP4rev2 is globally disabled", func(t *testing.T) {
		logs := &syncLogBuffer{}
		prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
		t.Cleanup(func() { logger.Swap(prev) })

		c := dialWireCapServer(t, IMAPServerOptions{
			DisabledCaps: []string{"MOVE"},
			CapabilityFilters: []config.ClientCapabilityFilter{{
				ClientName:  "^buggy$",
				DisableCaps: []string{"IMAP4rev1"},
				Reason:      "misconfigured rev1 removal",
			}},
		})
		if out := logs.String(); !strings.Contains(out, "IMAP4rev1") {
			t.Errorf("expected startup WARN mentioning IMAP4rev1, got:\n%s", out)
		}

		c.mustOK(`ID ("name" "buggy")`)
		caps := parseWireCaps(t, c.mustOK("CAPABILITY"))
		if !slices.Contains(caps, "IMAP4rev1") {
			t.Errorf("CAPABILITY lost IMAP4rev1: %v", caps)
		}
	})

	t.Run("keeps IMAP4rev1 when filter also disables an IMAP4rev2 extension", func(t *testing.T) {
		c := dialWireCapServer(t, IMAPServerOptions{
			CapabilityFilters: []config.ClientCapabilityFilter{{
				ClientName:  "^buggy$",
				DisableCaps: []string{"IMAP4rev1", "MOVE"},
			}},
		})
		c.mustOK(`ID ("name" "buggy")`)
		caps := parseWireCaps(t, c.mustOK("CAPABILITY"))
		for _, want := range []string{"IMAP4rev1", "ENABLE"} {
			if !slices.Contains(caps, want) {
				t.Errorf("CAPABILITY missing %s: %v", want, caps)
			}
		}
		for _, gone := range []string{"IMAP4rev2", "MOVE"} {
			if slices.Contains(caps, gone) {
				t.Errorf("CAPABILITY still advertises %s: %v", gone, caps)
			}
		}
	})

	t.Run("keeps IMAP4rev1 and ENABLE on dual-stack server so advertisement matches wire mode", func(t *testing.T) {
		c := dialWireCapServer(t, IMAPServerOptions{
			CapabilityFilters: []config.ClientCapabilityFilter{{
				ClientName:  "^buggy$",
				DisableCaps: []string{"IMAP4rev1"},
			}},
		})
		c.mustOK(`ID ("name" "buggy")`)
		caps := parseWireCaps(t, c.mustOK("CAPABILITY"))
		for _, want := range []string{"IMAP4rev1", "IMAP4rev2", "ENABLE"} {
			if !slices.Contains(caps, want) {
				t.Errorf("CAPABILITY missing %s while connection is IMAP4rev1 (IsIMAP4rev2=%v): %v", want, c.sess.conn.IsIMAP4rev2(), caps)
			}
		}
	})
}

// Disabling IMAP4rev1 together with IMAP4rev2 (directly or through any
// capability IMAP4rev2 implies) leaves no base IMAP version and panicked
// imapserver.New; New must return a clean error instead.
func TestDisabledCaps_RefusesRemovingBothIMAPVersions(t *testing.T) {
	newServer := func(disabled []string) (srv *IMAPServer, err error) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				err = nil
				t.Errorf("disabled_caps = %v panicked in New: %v", disabled, r)
			}
		}()
		srv, err = New(ctx, "disabled-both", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, IMAPServerOptions{
			AppendLimit:    DefaultAppendLimit,
			MaxConnections: 10,
			Config:         &config.Config{},
			DisabledCaps:   disabled,
		})
		if srv != nil {
			srv.Close()
		}
		return srv, err
	}

	for _, invalid := range [][]string{
		{"IMAP4rev1", "IMAP4rev2"},
		{"IMAP4rev1", "MOVE"},
		{"IMAP4rev1", "IDLE"},
		{"IMAP4rev1", "ESEARCH"},
		{"IMAP4rev1", "SEARCHRES"},
		{"IMAP4rev1", "CHILDREN"},
	} {
		if _, err := newServer(invalid); err == nil {
			t.Errorf("disabled_caps = %v: expected error when neither IMAP4rev1 nor IMAP4rev2 remains", invalid)
		}
	}

	for _, valid := range [][]string{
		{"IMAP4rev1"},
		{"IMAP4rev2"},
		{"MOVE"},
		{"IMAP4rev1", "SORT"},
		{"IMAP4rev1", "CONDSTORE"},
		{"IMAP4rev1", "SASL-IR"},
	} {
		srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: valid})
		if !srv.caps.Has(imap.CapIMAP4rev1) && !srv.caps.Has(imap.CapIMAP4rev2) {
			t.Errorf("disabled_caps = %v left no base IMAP version", valid)
		}
	}
}
