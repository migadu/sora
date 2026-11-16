package imap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
)

type wireListSession struct {
	*meteredSession
}

func (s *wireListSession) Login(_ context.Context, username, _ string) error {
	addr, err := serverPkg.NewAddress(username)
	if err != nil {
		addr, _ = serverPkg.NewAddress("user@example.com")
	}
	s.IMAPUser = NewIMAPUser(addr, 1)
	s.Session.User = &s.IMAPUser.User
	return nil
}

type wireListClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	tag  int
}

func dialWireListServer(t *testing.T, opts IMAPServerOptions) *wireListClient {
	t.Helper()
	srv := newDisabledCapsTestServer(t, opts)
	is := imapserver.New(&imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			sess, greeting, err := srv.newSession(c)
			if err != nil {
				return nil, nil, err
			}
			return &wireListSession{meteredSession: sess.(*meteredSession)}, greeting, nil
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

	c := &wireListClient{t: t, conn: conn, br: br}
	c.mustOK("LOGIN user@example.com secret")
	return c
}

func (c *wireListClient) sendCmd(cmd string) (resp, tagged string, err error) {
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

func (c *wireListClient) mustOK(cmd string) string {
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

func (c *wireListClient) mustBad(cmd string) {
	c.t.Helper()
	resp, tagged, err := c.sendCmd(cmd)
	if err != nil {
		c.t.Fatalf("%s failed with I/O error %v; partial response:\n%s", cmd, err, resp)
	}
	if !strings.Contains(tagged, " BAD ") {
		c.t.Fatalf("%s: want BAD, got:\n%s", cmd, resp)
	}
}

// RFC 5258 §3 and RFC 9051 §6.3.9.1: "An empty ("" string) mailbox name
// argument has no special meaning when any selection or return options are
// specified; thus, the command LIST "" "" RETURN (SUBSCRIBED) will return no
// LIST responses, as there is no mailbox with an empty name." Plain LIST ref ""
// without selection or return options (including empty () / RETURN () option
// lists) still returns the \Noselect hierarchy-delimiter response.
func TestList_ExtendedEmptyPatternReturnsNoResponses(t *testing.T) {
	for name, opts := range map[string]IMAPServerOptions{
		"default capabilities": {},
		"CHILDREN disabled":    {DisabledCaps: []string{"CHILDREN"}},
	} {
		t.Run(name, func(t *testing.T) {
			c := dialWireListServer(t, opts)

			for _, cmd := range []string{
				`LIST "" "" RETURN (CHILDREN)`,
				`LIST "" "" RETURN (SUBSCRIBED)`,
				`LIST "" "" RETURN (SPECIAL-USE)`,
				`LIST "" "" RETURN (STATUS (MESSAGES UNSEEN))`,
				`LIST (SUBSCRIBED) "" ""`,
				`LIST (SUBSCRIBED RECURSIVEMATCH) "" ""`,
				`LIST (REMOTE) "" ""`,
				`LIST (SPECIAL-USE) "" ""`,
				`LIST (SUBSCRIBED) "" "" RETURN (CHILDREN)`,
				`LIST "Work" "" RETURN (CHILDREN)`,
				`LIST "Work/" "" RETURN (CHILDREN)`,
				`LIST (SUBSCRIBED) "Work/" ""`,
			} {
				if resp := c.mustOK(cmd); strings.Contains(resp, "* LIST ") {
					t.Errorf("%s returned untagged LIST response, want none:\n%s", cmd, resp)
				}
			}

			for _, cmd := range []string{
				`LIST "" ""`,
				`LIST "Work/" ""`,
				`LIST () "" ""`,
				`LIST "" "" RETURN ()`,
			} {
				const want = "* LIST (\\Noselect) \"/\" \"\"\r\n"
				if resp := c.mustOK(cmd); !strings.Contains(resp, want) {
					t.Errorf("%s: want %q, got:\n%s", cmd, want, resp)
				}
			}
		})
	}
}

// Capability checks on LIST selection and return options must still run before
// the empty-pattern return so unsupported options on "" are refused with BAD
// (RFC 5258 §3).
func TestList_ExtendedEmptyPatternStillEnforcesCapabilityGates(t *testing.T) {
	t.Run("LIST-METADATA not advertised", func(t *testing.T) {
		c := dialWireListServer(t, IMAPServerOptions{})
		c.mustBad(`LIST "" "" RETURN (METADATA ("/private/comment"))`)
	})

	t.Run("SPECIAL-USE disabled", func(t *testing.T) {
		c := dialWireListServer(t, IMAPServerOptions{DisabledCaps: []string{"SPECIAL-USE"}})
		c.mustBad(`LIST (SPECIAL-USE) "" ""`)
		c.mustBad(`LIST "" "" RETURN (SPECIAL-USE)`)
	})

	t.Run("LIST-STATUS disabled", func(t *testing.T) {
		c := dialWireListServer(t, IMAPServerOptions{DisabledCaps: []string{"LIST-STATUS"}})
		c.mustBad(`LIST "" "" RETURN (STATUS (MESSAGES))`)
	})

	t.Run("STATUS=SIZE disabled", func(t *testing.T) {
		c := dialWireListServer(t, IMAPServerOptions{DisabledCaps: []string{"STATUS=SIZE"}})
		c.mustBad(`LIST "" "" RETURN (STATUS (SIZE))`)
	})
}

// Matching an explicit empty pattern []string{""} against non-empty mailboxes
// and subscriptions (e.g. via LSUB or direct List callers) matches nothing for
// both empty and non-empty reference names.
func TestList_EmptyPatternMatchesNoMailbox(t *testing.T) {
	mboxes := []*db.DBMailbox{
		{ID: 1, Name: "INBOX", NameKey: "inbox", Subscribed: true},
		{ID: 2, Name: "Work", NameKey: "work", HasChildren: true, Subscribed: true},
		{ID: 3, Name: "Work/Sub", NameKey: "work/sub", Subscribed: true},
	}
	subscribed := map[string]string{
		"inbox":    "INBOX",
		"work":     "Work",
		"work/sub": "Work/Sub",
	}
	caps := newDisabledCapsTestServer(t, IMAPServerOptions{}).caps

	for _, ref := range []string{"", "Work", "Work/"} {
		for _, m := range mboxes {
			if matchesAnyPattern(m.Name, ref, []string{""}) {
				t.Errorf("matchesAnyPattern(%q, %q, [\"\"]) = true, want false", m.Name, ref)
			}
		}
		got := buildSubscribedList(ref, []string{""}, &imap.ListOptions{
			SelectSubscribed:     true,
			SelectRecursiveMatch: true,
			ReturnChildren:       true,
		}, mboxes, subscribed, caps, "")
		if len(got) != 0 {
			t.Errorf("buildSubscribedList(ref=%q, patterns=[\"\"]) = %+v, want empty", ref, got)
		}
	}
}
