package imap

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

func dialWireSharedServer(t *testing.T, shared config.SharedMailboxesConfig) *wireListClient {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, err := New(
		ctx,
		"shared-root-wire",
		"localhost",
		"127.0.0.1:0",
		&storage.S3Storage{},
		&resilient.ResilientDatabase{},
		&uploader.UploadWorker{},
		&cache.Cache{},
		IMAPServerOptions{
			AppendLimit:    DefaultAppendLimit,
			MaxConnections: 10,
			Config:         &config.Config{SharedMailboxes: shared},
		},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(srv.Close)

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

// The shared namespace root ("Shared" for "Shared/", or a custom multi-level
// prefix root like "Public/Rooms") is never selectable (SELECT refuses it with
// NO [CANNOT] regardless of whether children currently exist under it).
// listMailbox must therefore keep \Noselect on that root even after its last
// child mailbox is deleted (HasChildren == false), while leaving personal
// mailboxes above a multi-segment prefix ("Public") and personal mailboxes
// when shared mailboxes are disabled (sharedNamespaceRoot == "") selectable.
func TestListMailbox_SharedNamespaceRootAlwaysNoSelect(t *testing.T) {
	caps := newDisabledCapsTestServer(t, IMAPServerOptions{}).caps

	for _, tc := range []struct {
		name           string
		mbox           *db.DBMailbox
		sharedRoot     string
		wantNoSelect   bool
		wantChildTrait imap.MailboxAttr
	}{
		{
			name:           "shared root with children",
			mbox:           &db.DBMailbox{ID: 1, Name: "Shared", HasChildren: true},
			sharedRoot:     "Shared",
			wantNoSelect:   true,
			wantChildTrait: imap.MailboxAttrHasChildren,
		},
		{
			name:           "shared root without children after last child deleted",
			mbox:           &db.DBMailbox{ID: 1, Name: "Shared", HasChildren: false},
			sharedRoot:     "Shared",
			wantNoSelect:   true,
			wantChildTrait: imap.MailboxAttrHasNoChildren,
		},
		{
			name:           "shared root case-insensitive match without children",
			mbox:           &db.DBMailbox{ID: 2, Name: "shared", HasChildren: false},
			sharedRoot:     "Shared",
			wantNoSelect:   true,
			wantChildTrait: imap.MailboxAttrHasNoChildren,
		},
		{
			name:           "multi-segment shared root without children",
			mbox:           &db.DBMailbox{ID: 3, Name: "Public/Rooms", HasChildren: false},
			sharedRoot:     "Public/Rooms",
			wantNoSelect:   true,
			wantChildTrait: imap.MailboxAttrHasNoChildren,
		},
		{
			name:           "personal ancestor above multi-segment shared root",
			mbox:           &db.DBMailbox{ID: 4, Name: "Public", HasChildren: true},
			sharedRoot:     "Public/Rooms",
			wantNoSelect:   false,
			wantChildTrait: imap.MailboxAttrHasChildren,
		},
		{
			name:           "personal mailbox named Shared when sharing is disabled",
			mbox:           &db.DBMailbox{ID: 5, Name: "Shared", HasChildren: true},
			sharedRoot:     "",
			wantNoSelect:   false,
			wantChildTrait: imap.MailboxAttrHasChildren,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := listMailbox(tc.mbox, &imap.ListOptions{}, caps, tc.sharedRoot)
			if data == nil {
				t.Fatalf("listMailbox(%q) returned nil", tc.mbox.Name)
			}
			gotNoSelect := slices.Contains(data.Attrs, imap.MailboxAttrNoSelect)
			if gotNoSelect != tc.wantNoSelect {
				t.Errorf("listMailbox(%q, sharedRoot=%q) attrs=%v: has \\Noselect=%v, want %v",
					tc.mbox.Name, tc.sharedRoot, data.Attrs, gotNoSelect, tc.wantNoSelect)
			}
			if !slices.Contains(data.Attrs, tc.wantChildTrait) {
				t.Errorf("listMailbox(%q, sharedRoot=%q) attrs=%v: missing %s",
					tc.mbox.Name, tc.sharedRoot, data.Attrs, tc.wantChildTrait)
			}
		})
	}
}

// Direct STATUS on the configured shared-namespace root must be refused with
// NO [CANNOT] and no untagged STATUS line, matching SELECT/EXAMINE, while still
// rejecting unsupported STATUS items with BAD first.
func TestStatus_SharedNamespaceRootRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
		probes []string
	}{
		{
			name:   "default Shared prefix",
			prefix: "Shared/",
			probes: []string{
				`STATUS "Shared" (MESSAGES DELETED)`,
				`STATUS "shared" (MESSAGES)`,
			},
		},
		{
			name:   "multi-segment prefix",
			prefix: "Public/Rooms/",
			probes: []string{
				`STATUS "Public/Rooms" (MESSAGES)`,
				`STATUS "public/rooms" (MESSAGES DELETED)`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dialWireSharedServer(t, config.SharedMailboxesConfig{
				Enabled:         true,
				NamespacePrefix: tc.prefix,
			})

			// Argument/capability checks must still run before mailbox refusal.
			c.mustBad(`STATUS "Shared" (DELETED-STORAGE)`)

			for _, cmd := range tc.probes {
				resp, tagged, err := c.sendCmd(cmd)
				if err != nil {
					t.Fatalf("%s failed with I/O error %v; partial:\n%s", cmd, err, resp)
				}
				if strings.Contains(resp, "* STATUS ") {
					t.Errorf("%s emitted untagged STATUS response:\n%s", cmd, resp)
				}
				if !strings.Contains(tagged, " NO [CANNOT] ") {
					t.Errorf("%s: want tagged NO [CANNOT], got:\n%s", cmd, resp)
				}
			}
		})
	}
}

// RFC 9051 has no RECENT status data item: Appendix E item 12 deprecates
// "RECENT STATUS", and its grammar gives the LIST STATUS return option the
// STATUS items ("status-option = "STATUS" SP "(" status-att *(SP status-att)
// ")"", §9), where status-att is only MESSAGES, UIDNEXT, UIDVALIDITY, UNSEEN,
// DELETED and SIZE. go-imap refuses STATUS (RECENT) once the client has
// ENABLEd IMAP4rev2, and LIST RETURN (STATUS) "takes STATUS data items as
// parameters" (RFC 9051 §6.3.9.2, RFC 5819 §2), so it must refuse RECENT the
// same way (#1179). An IMAP4rev1 session keeps RECENT on both.
func TestList_ReturnStatusRefusesRecentUnderIMAP4rev2(t *testing.T) {
	c := dialWireListServer(t, IMAPServerOptions{})

	// The empty pattern answers no LIST line once the arguments have been
	// checked ("In the extended syntax, any mailbox name arguments that are
	// empty strings are ignored", RFC 9051 §6.3.9; RFC 5258 §3), so the session
	// needs no mailbox behind it.
	const listRecent = `LIST "" "" RETURN (STATUS (MESSAGES RECENT))`
	c.mustOK(listRecent)

	c.mustOK("ENABLE IMAP4rev2")
	c.mustBad("STATUS INBOX (MESSAGES RECENT)")
	c.mustBad(listRecent)
	c.mustBad(`LIST "" "" RETURN (STATUS (RECENT))`)
	c.mustOK(`LIST "" "" RETURN (STATUS (MESSAGES DELETED))`)
}

// A server that offers no IMAP4rev1 (disabled_caps = ["IMAP4rev1"]) serves
// every session IMAP4rev2 without an ENABLE, and go-imap refuses STATUS
// (RECENT) there too; LIST RETURN (STATUS (RECENT)) must follow it (#1179).
func TestList_ReturnStatusRefusesRecentOnRev2OnlyServer(t *testing.T) {
	c := dialWireListServer(t, IMAPServerOptions{DisabledCaps: []string{"IMAP4rev1"}})

	c.mustBad("STATUS INBOX (MESSAGES RECENT)")
	c.mustBad(`LIST "" "" RETURN (STATUS (MESSAGES RECENT))`)
	c.mustOK(`LIST "" "" RETURN (STATUS (MESSAGES DELETED))`)
}
