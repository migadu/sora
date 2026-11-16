package imap

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
)

func TestSharedNamespaceRootMatchesConfigCaseRules(t *testing.T) {
	caps := newDisabledCapsTestServer(t, IMAPServerOptions{}).caps

	for _, tc := range []struct {
		prefix string
		name   string
		isRoot bool
	}{
		{"Shared/", "Shared", true},
		{"Shared/", "sHARED", true},
		{"Shared/", "ſhared", false},
		{"ΑΣ/", "ασ", true},
		{"ΑΣ/", "ας", false},
		{"İx/", "ix", true},
		{"İx/", "İX", true},
		{"Public/Rooms/", "PUBLIC/rooms", true},
		{"Public/Rooms/", "Public/ſhared", false},
	} {
		t.Run(tc.prefix+"_"+tc.name, func(t *testing.T) {
			cfg := config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: tc.prefix, AllowUserCreate: true}
			if got := cfg.IsNamespaceRoot(tc.name); got != tc.isRoot {
				t.Fatalf("config.IsNamespaceRoot(%q) = %v, want %v", tc.name, got, tc.isRoot)
			}

			sharedRoot := strings.TrimSuffix(tc.prefix, "/")

			// 1. listMailbox \Noselect classification
			data := listMailbox(&db.DBMailbox{ID: 1, Name: tc.name}, &imap.ListOptions{}, caps, sharedRoot)
			if data == nil {
				t.Fatalf("listMailbox(%q) returned nil", tc.name)
			}
			if got := slices.Contains(data.Attrs, imap.MailboxAttrNoSelect); got != tc.isRoot {
				t.Errorf("listMailbox(%q, sharedRoot=%q) \\Noselect = %v, want %v (attrs=%v)",
					tc.name, sharedRoot, got, tc.isRoot, data.Attrs)
			}

			// 2. notifyDiffSnapshots \Noselect classification
			prev := map[int64]notifySnapshotEntry{}
			cur := map[int64]notifySnapshotEntry{1: {name: tc.name}}
			notifyLists := runNotifyDiffSnapshots(
				t,
				[]imap.NotifyItem{{
					MailboxSpec: imap.NotifyMailboxSpecSubscribed,
					Events:      []imap.NotifyEvent{imap.NotifyEventMailboxName},
				}},
				prev,
				map[int64]notifySnapshotEntry{1: {name: cur[1].name, subscribed: true}},
				sharedRoot,
			)
			if len(notifyLists) != 1 {
				t.Fatalf("notifyDiffSnapshots(%q) returned %d items, want 1", tc.name, len(notifyLists))
			}
			if got := slices.Contains(notifyLists[0].Attrs, imap.MailboxAttrNoSelect); got != tc.isRoot {
				t.Errorf("notifyDiffSnapshots(%q, sharedRoot=%q) \\Noselect = %v, want %v (attrs=%v)",
					tc.name, sharedRoot, got, tc.isRoot, notifyLists[0].Attrs)
			}

			// 3. Session command guards: CREATE, SELECT, STATUS
			s := newPersonalTestSession(t, 1, cfg)
			for _, probe := range []struct {
				cmd string
				fn  func() error
			}{
				{"CREATE", func() error { return s.Create(context.Background(), tc.name, nil) }},
				{"SELECT", func() error { _, err := s.Select(context.Background(), tc.name, nil); return err }},
				{"STATUS", func() error {
					_, err := s.Status(context.Background(), tc.name, &imap.StatusOptions{NumMessages: true})
					return err
				}},
			} {
				err, hitDB := callUntilDB(probe.fn)
				var imapErr *imap.Error
				gotCannot := !hitDB && errors.As(err, &imapErr) && imapErr.Code == imap.ResponseCodeCannot
				if gotCannot != tc.isRoot {
					t.Errorf("%s(%q) under prefix %q: refused [CANNOT]=%v (hitDB=%v, err=%v), want %v",
						probe.cmd, tc.name, tc.prefix, gotCannot, hitDB, err, tc.isRoot)
				}
			}
		})
	}

	// Sharing disabled (sharedRoot == "") must never mark names (including "") \Noselect.
	for _, name := range []string{"Shared", "ix", ""} {
		data := listMailbox(&db.DBMailbox{ID: 1, Name: name}, &imap.ListOptions{}, caps, "")
		if slices.Contains(data.Attrs, imap.MailboxAttrNoSelect) {
			t.Errorf("sharing disabled: listMailbox(%q) falsely marked \\Noselect: %v", name, data.Attrs)
		}
	}

	// 4. isRefusedSharedRoot must stop walking ancestors at the shared namespace root
	// even when lowercasing changes UTF-8 byte width ("İx/" vs "ix/Second").
	s := newPersonalTestSession(t, 1, config.SharedMailboxesConfig{
		Enabled:         true,
		NamespacePrefix: "İx/",
		AllowUserCreate: false,
	})
	var refused bool
	err, hitDB := callUntilDB(func() error {
		var rErr error
		refused, rErr = s.isRefusedSharedRoot(context.Background(), 1, "ix/Second", false)
		return rErr
	})
	if hitDB || err != nil || !refused {
		t.Errorf("isRefusedSharedRoot(\"ix/Second\") under \"İx/\": refused=%v, hitDB=%v, err=%v; want refused=true without querying parent \"ix\"",
			refused, hitDB, err)
	}
}

// callUntilDB invokes fn against a session with nil rdb, catching the nil-deref
// once execution passes the in-memory namespace-root guard and reaches the DB.
func callUntilDB(fn func() error) (err error, hitDB bool) {
	defer func() {
		if r := recover(); r != nil {
			hitDB = true
		}
	}()
	return fn(), false
}
