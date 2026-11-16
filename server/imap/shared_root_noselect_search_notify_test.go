package imap

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
)

// startNameKeyPostgres runs an in-process PostgreSQL wire stub on 127.0.0.1:0
// that answers pool pings and db.Database.MailboxNameKeys(ctx, names) using
// keyFn, so resolveSearchSource unit tests exercise SUBTREE, SUBTREE-ONE and
// MAILBOXES without an external PostgreSQL server.
func startNameKeyPostgres(t *testing.T, keyFn func(string) string) *resilient.ResilientDatabase {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveNameKeyPostgres(conn, keyFn)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dbCfg := &config.DatabaseConfig{
		ReadsShareWritePool: true,
		Write: &config.DatabaseEndpointConfig{
			Hosts:          []string{tcpAddr.IP.String()},
			Port:           tcpAddr.Port,
			User:           "postgres",
			Name:           "sora_unit_test",
			TLSMode:        false,
			MaxConnections: 2,
		},
	}
	rdb, err := resilient.NewResilientDatabaseWithOptions(ctx, dbCfg, false, false, true)
	if err != nil {
		t.Fatalf("NewResilientDatabaseWithOptions: %v", err)
	}
	t.Cleanup(rdb.Close)
	return rdb
}

func serveNameKeyPostgres(conn net.Conn, keyFn func(string) string) {
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
	if _, ok := msg.(*pgproto3.StartupMessage); !ok {
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return
	}

	typeMap := pgtype.NewMap()
	stmts := make(map[string]bool) // statement name -> is unnest LOWER query
	type portalState struct {
		isUnnest bool
		encoded  []byte
		format   int16
	}
	portals := make(map[string]portalState)

	rowDesc := func(format int16) *pgproto3.RowDescription {
		return &pgproto3.RowDescription{
			Fields: []pgproto3.FieldDescription{{
				Name:         []byte("array"),
				DataTypeOID:  pgtype.TextArrayOID,
				DataTypeSize: -1,
				TypeModifier: -1,
				Format:       format,
			}},
		}
	}

	for {
		raw, err := backend.Receive()
		if err != nil {
			return
		}
		switch m := raw.(type) {
		case *pgproto3.Query:
			backend.Send(&pgproto3.EmptyQueryResponse{})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backend.Flush(); err != nil {
				return
			}
		case *pgproto3.Parse:
			stmts[m.Name] = strings.Contains(m.Query, "unnest")
			backend.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Describe:
			switch m.ObjectType {
			case 'S':
				if stmts[m.Name] {
					backend.Send(&pgproto3.ParameterDescription{ParameterOIDs: []uint32{pgtype.TextArrayOID}})
					backend.Send(rowDesc(pgtype.TextFormatCode))
				} else {
					backend.Send(&pgproto3.ParameterDescription{})
					backend.Send(&pgproto3.NoData{})
				}
			case 'P':
				if p := portals[m.Name]; p.isUnnest {
					backend.Send(rowDesc(p.format))
				} else {
					backend.Send(&pgproto3.NoData{})
				}
			}
		case *pgproto3.Bind:
			isUnnest := stmts[m.PreparedStatement]
			resFmt := int16(pgtype.TextFormatCode)
			if len(m.ResultFormatCodes) > 0 {
				resFmt = m.ResultFormatCodes[0]
			}
			var encoded []byte
			if isUnnest && len(m.Parameters) == 1 {
				paramFmt := int16(pgtype.TextFormatCode)
				if len(m.ParameterFormatCodes) > 0 {
					paramFmt = m.ParameterFormatCodes[0]
				}
				var names []string
				plan := typeMap.PlanScan(pgtype.TextArrayOID, paramFmt, &names)
				if err := plan.Scan(m.Parameters[0], &names); err != nil {
					return
				}
				lowered := make([]string, len(names))
				for i, n := range names {
					lowered[i] = keyFn(n)
				}
				var encErr error
				encoded, encErr = typeMap.Encode(pgtype.TextArrayOID, resFmt, lowered, nil)
				if encErr != nil {
					return
				}
			}
			portals[m.DestinationPortal] = portalState{isUnnest: isUnnest, encoded: encoded, format: resFmt}
			backend.Send(&pgproto3.BindComplete{})
		case *pgproto3.Execute:
			if p := portals[m.Portal]; p.isUnnest {
				backend.Send(&pgproto3.DataRow{Values: [][]byte{p.encoded}})
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			} else {
				backend.Send(&pgproto3.EmptyQueryResponse{})
			}
		case *pgproto3.Close:
			if m.ObjectType == 'S' {
				delete(stmts, m.Name)
			} else {
				delete(portals, m.Name)
			}
			backend.Send(&pgproto3.CloseComplete{})
		case *pgproto3.Sync:
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backend.Flush(); err != nil {
				return
			}
		case *pgproto3.Flush:
			if err := backend.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

func newSearchSourceTestSession(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, shared config.SharedMailboxesConfig) *IMAPSession {
	t.Helper()
	addr, err := serverPkg.NewAddress("user@example.com")
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	s := &IMAPSession{
		server: &IMAPServer{
			rdb:    rdb,
			config: &config.Config{SharedMailboxes: shared},
		},
	}
	s.IMAPUser = NewIMAPUser(addr, accountID)
	s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, context.Background(), "IMAP", func(string, ...any) {})
	return s
}

// TestResolveSearchSourceExcludesNoSelectSharedRoot verifies that ESEARCH IN (...)
// omits the \Noselect shared namespace root across SUBTREE, SUBTREE-ONE,
// SUBSCRIBED, and MAILBOXES under Sora's hierarchy-only shared-root policy,
// while keeping selectable
// mailboxes under the shared root, personal mailboxes with lookalike names, and
// the personal mailbox of the same name when shared mailboxes are disabled.
func TestResolveSearchSourceExcludesNoSelectSharedRoot(t *testing.T) {
	const me = 1
	icuKey := func(name string) string {
		// Stand in for PostgreSQL/ICU LOWER(name), including final sigma and
		// dotted capital I where Go's strings.ToLower and ICU differ.
		switch name {
		case "ΑΣ":
			return "ας"
		case "ΑΣ/Team":
			return "ας/team"
		case "İx":
			return "i\u0307x"
		default:
			return strings.ToLower(name)
		}
	}
	rdb := startNameKeyPostgres(t, icuKey)

	mbox := func(id int64, name string, subscribed bool) *db.DBMailbox {
		return &db.DBMailbox{
			ID:         id,
			AccountID:  me,
			Name:       name,
			NameKey:    icuKey(name),
			Subscribed: subscribed,
		}
	}

	t.Run("DefaultSharedPrefix", func(t *testing.T) {
		shared := config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"}
		s := newSearchSourceTestSession(t, rdb, me, shared)
		all := []*db.DBMailbox{
			mbox(1, "INBOX", true),
			mbox(2, "Shared", true),          // \Noselect shared namespace root (even if subscribed)
			mbox(3, "Shared/Team", true),     // selectable child
			mbox(4, "Shared/Team/Sub", true), // selectable grandchild
			mbox(5, "ſhared", true),          // U+017F long s: personal selectable mailbox, not Shared
		}

		for _, tc := range []struct {
			name   string
			source *imap.SearchSource
			want   []string
		}{
			{
				name:   "SubtreeRoot",
				source: &imap.SearchSource{Subtree: []string{"Shared"}},
				want:   []string{"Shared/Team", "Shared/Team/Sub"},
			},
			{
				name:   "SubtreeRootCaseInsensitive",
				source: &imap.SearchSource{Subtree: []string{"sHaReD"}},
				want:   []string{"Shared/Team", "Shared/Team/Sub"},
			},
			{
				name:   "SubtreeOneRoot",
				source: &imap.SearchSource{SubtreeOne: []string{"Shared"}},
				want:   []string{"Shared/Team"},
			},
			{
				name:   "Subscribed",
				source: &imap.SearchSource{Subscribed: true},
				want:   []string{"INBOX", "Shared/Team", "Shared/Team/Sub", "ſhared"},
			},
			{
				name:   "MailboxesExplicit",
				source: &imap.SearchSource{Mailboxes: []string{"Shared", "Shared/Team", "ſhared"}},
				want:   []string{"Shared/Team", "ſhared"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := s.resolveSearchSource(context.Background(), tc.source, all)
				if err != nil {
					t.Fatalf("resolveSearchSource: %v", err)
				}
				var names []string
				for _, m := range got {
					names = append(names, m.Name)
				}
				if !slices.Equal(names, tc.want) {
					t.Errorf("got %q, want %q", names, tc.want)
				}
			})
		}
	})

	t.Run("MultiLevelSharedPrefix", func(t *testing.T) {
		shared := config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Org/Shared/"}
		s := newSearchSourceTestSession(t, rdb, me, shared)
		all := []*db.DBMailbox{
			mbox(1, "Org", true),             // above shared root: selectable personal mailbox
			mbox(2, "Org/Notes", true),       // sibling of shared root: selectable personal mailbox
			mbox(3, "org/SHARED", true),      // \Noselect shared namespace root (stored in mixed case)
			mbox(4, "Org/Shared/Team", true), // selectable shared mailbox
		}

		for _, tc := range []struct {
			name   string
			source *imap.SearchSource
			want   []string
		}{
			{
				name:   "SubtreeParentOfSharedRoot",
				source: &imap.SearchSource{Subtree: []string{"Org"}},
				want:   []string{"Org", "Org/Notes", "Org/Shared/Team"},
			},
			{
				name:   "SubtreeOneParentOfSharedRoot",
				source: &imap.SearchSource{SubtreeOne: []string{"Org"}},
				want:   []string{"Org", "Org/Notes"},
			},
			{
				name:   "SubtreeSharedRoot",
				source: &imap.SearchSource{Subtree: []string{"Org/Shared"}},
				want:   []string{"Org/Shared/Team"},
			},
			{
				name:   "SubtreeOneSharedRoot",
				source: &imap.SearchSource{SubtreeOne: []string{"Org/Shared"}},
				want:   []string{"Org/Shared/Team"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := s.resolveSearchSource(context.Background(), tc.source, all)
				if err != nil {
					t.Fatalf("resolveSearchSource: %v", err)
				}
				var names []string
				for _, m := range got {
					names = append(names, m.Name)
				}
				if !slices.Equal(names, tc.want) {
					t.Errorf("got %q, want %q", names, tc.want)
				}
			})
		}
	})

	t.Run("UnicodeDottedCapitalIPrefix", func(t *testing.T) {
		// Under creation policy strings.ToLower("İx") == "ix", so "ix" is the
		// \Noselect shared namespace root for prefix "İx/".
		shared := config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "İx/"}
		s := newSearchSourceTestSession(t, rdb, me, shared)
		all := []*db.DBMailbox{
			mbox(1, "ix", true),
			mbox(2, "ix/Team", true),
		}
		got, err := s.resolveSearchSource(context.Background(), &imap.SearchSource{
			Subscribed: true,
			Subtree:    []string{"ix"},
			SubtreeOne: []string{"ix"},
			Mailboxes:  []string{"ix", "ix/Team"},
		}, all)
		if err != nil {
			t.Fatalf("resolveSearchSource: %v", err)
		}
		var names []string
		for _, m := range got {
			names = append(names, m.Name)
		}
		if want := []string{"ix/Team"}; !slices.Equal(names, want) {
			t.Errorf("got %q, want %q", names, want)
		}
	})

	t.Run("SharingDisabledKeepsPersonalMailbox", func(t *testing.T) {
		shared := config.SharedMailboxesConfig{Enabled: false, NamespacePrefix: "Shared/"}
		s := newSearchSourceTestSession(t, rdb, me, shared)
		all := []*db.DBMailbox{
			mbox(1, "Shared", true),
			mbox(2, "Shared/Team", true),
		}
		for _, src := range []*imap.SearchSource{
			{Subtree: []string{"Shared"}},
			{SubtreeOne: []string{"Shared"}},
			{Subscribed: true},
			{Mailboxes: []string{"Shared", "Shared/Team"}},
		} {
			got, err := s.resolveSearchSource(context.Background(), src, all)
			if err != nil {
				t.Fatalf("resolveSearchSource(%+v): %v", src, err)
			}
			var names []string
			for _, m := range got {
				names = append(names, m.Name)
			}
			if want := []string{"Shared", "Shared/Team"}; !slices.Equal(names, want) {
				t.Errorf("sharing disabled (%+v): got %q, want %q", src, names, want)
			}
		}
	})
}

// TestNotifyEventsForMailboxNoSelectSharedRoot verifies that NOTIFY omits
// message events (MessageNew, MessageExpunge and FlagChange, whose unselected
// mailbox notifications use STATUS) on
// the \Noselect shared namespace root across SUBTREE, SUBSCRIBED, and MAILBOXES,
// while preserving hierarchy events (MailboxName and SubscriptionChange,
// RFC 5465 §5.4–§5.5).
func TestNotifyEventsForMailboxNoSelectSharedRoot(t *testing.T) {
	msgOnly := []imap.NotifyEvent{
		imap.NotifyEventMessageNew,
		imap.NotifyEventMessageExpunge,
		imap.NotifyEventFlagChange,
	}
	allEvents := []imap.NotifyEvent{
		imap.NotifyEventMessageNew,
		imap.NotifyEventMessageExpunge,
		imap.NotifyEventFlagChange,
		imap.NotifyEventMailboxName,
		imap.NotifyEventSubscriptionChange,
	}
	treeOnly := []imap.NotifyEvent{
		imap.NotifyEventMailboxName,
		imap.NotifyEventSubscriptionChange,
	}

	tests := []struct {
		name       string
		watch      *notifyWatch
		mailbox    string
		key        string
		subscribed bool
		sharedRoot string
		want       []imap.NotifyEvent
		wantStatus bool
	}{
		{
			name:       "SubtreeMessageEventsOmittedOnSharedRoot",
			watch:      newTestWatch(imap.NotifyItem{Mailboxes: []string{"Shared"}, Subtree: true, Events: msgOnly}),
			mailbox:    "Shared",
			subscribed: true,
			sharedRoot: "Shared",
			want:       nil,
			wantStatus: false,
		},
		{
			name:       "SubtreeTreeEventsPreservedOnSharedRoot",
			watch:      newTestWatch(imap.NotifyItem{Mailboxes: []string{"Shared"}, Subtree: true, Events: allEvents}),
			mailbox:    "sHaReD",
			subscribed: true,
			sharedRoot: "Shared",
			want:       treeOnly,
			wantStatus: false,
		},
		{
			name:       "SubtreeChildKeepsMessageAndTreeEvents",
			watch:      newTestWatch(imap.NotifyItem{Mailboxes: []string{"Shared"}, Subtree: true, Events: allEvents}),
			mailbox:    "Shared/Team",
			subscribed: true,
			sharedRoot: "Shared",
			want:       allEvents,
			wantStatus: true,
		},
		{
			name:       "SubscribedMessageEventsOmittedOnSharedRoot",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: msgOnly}),
			mailbox:    "Shared",
			subscribed: true,
			sharedRoot: "Shared",
			want:       nil,
			wantStatus: false,
		},
		{
			name:       "SubscribedTreeEventsPreservedOnSharedRoot",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: allEvents}),
			mailbox:    "Shared",
			subscribed: true,
			sharedRoot: "Shared",
			want:       treeOnly,
			wantStatus: false,
		},
		{
			name:       "MailboxesMessageEventsOmittedOnSharedRoot",
			watch:      newTestWatch(imap.NotifyItem{Mailboxes: []string{"Shared"}, Events: msgOnly}),
			mailbox:    "Shared",
			subscribed: false,
			sharedRoot: "Shared",
			want:       nil,
			wantStatus: false,
		},
		{
			name:       "MailboxesTreeEventsPreservedOnSharedRoot",
			watch:      newTestWatch(imap.NotifyItem{Mailboxes: []string{"Shared"}, Events: allEvents}),
			mailbox:    "Shared",
			subscribed: false,
			sharedRoot: "Shared",
			want:       treeOnly,
			wantStatus: false,
		},
		{
			name:       "MultiLevelSubtreeParentKeepsPersonalAndChildEventsOnly",
			watch:      newTestWatch(imap.NotifyItem{Mailboxes: []string{"Org"}, Subtree: true, Events: allEvents}),
			mailbox:    "org/SHARED",
			subscribed: true,
			sharedRoot: "Org/Shared",
			want:       treeOnly,
			wantStatus: false,
		},
		{
			name:       "UnicodeDottedCapitalIRootOmitted",
			watch:      newTestWatch(imap.NotifyItem{Mailboxes: []string{"ix"}, Subtree: true, Events: allEvents}),
			mailbox:    "ix",
			key:        "ix",
			subscribed: true,
			sharedRoot: "İx",
			want:       treeOnly,
			wantStatus: false,
		},
		{
			name:       "LongSLookalikeKeepsMessageEvents",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: msgOnly}),
			mailbox:    "ſhared",
			key:        "ſhared",
			subscribed: true,
			sharedRoot: "Shared",
			want:       msgOnly,
			wantStatus: true,
		},
		{
			name:       "FinalSigmaLookalikeKeepsMessageEvents",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: msgOnly}),
			mailbox:    "ας",
			key:        "ας",
			subscribed: true,
			sharedRoot: "ΑΣ",
			want:       msgOnly,
			wantStatus: true,
		},
		{
			name:       "SharingDisabledKeepsMessageEventsOnPersonalShared",
			watch:      newTestWatch(imap.NotifyItem{Mailboxes: []string{"Shared"}, Subtree: true, Events: msgOnly}),
			mailbox:    "Shared",
			subscribed: true,
			sharedRoot: "",
			want:       msgOnly,
			wantStatus: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.key
			if key == "" {
				key = testNameKey(tc.mailbox)
			}
			got := tc.watch.eventsForMailbox(tc.mailbox, key, tc.subscribed, tc.sharedRoot)
			if len(got) != len(tc.want) {
				t.Fatalf("eventsForMailbox(%q, sharedRoot=%q) = %v, want %v", tc.mailbox, tc.sharedRoot, got, tc.want)
			}
			for _, ev := range tc.want {
				if !got[ev] {
					t.Errorf("eventsForMailbox(%q) missing %v in %v", tc.mailbox, ev, got)
				}
			}
			gotStatus := notifyStatusOptions(got, false) != nil
			if gotStatus != tc.wantStatus {
				t.Errorf("notifyStatusOptions(%q) != nil is %v, want %v", tc.mailbox, gotStatus, tc.wantStatus)
			}
		})
	}

	// Filtering message events on the \Noselect shared namespace root must not
	// allocate on every pump tick when only message events were requested.
	watch := newTestWatch(imap.NotifyItem{Mailboxes: []string{"Shared"}, Subtree: true, Events: msgOnly})
	if n := testing.AllocsPerRun(100, func() {
		_ = watch.eventsForMailbox("Shared", "shared", true, "Shared")
	}); n != 0 {
		t.Errorf("eventsForMailbox on shared root with message-only watch allocates %v times, want 0", n)
	}
}
