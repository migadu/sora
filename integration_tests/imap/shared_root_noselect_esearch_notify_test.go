//go:build integration

package imap_test

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	imapsrv "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

var statusLineMailboxRe = regexp.MustCompile(`^\* STATUS (?:"([^"]*)"|([^ ]+)) \(`)

func statusMailboxes(t *testing.T, lines []string) map[string]string {
	t.Helper()
	got := make(map[string]string)
	for _, line := range lines {
		if !strings.HasPrefix(line, "* STATUS ") {
			continue
		}
		m := statusLineMailboxRe.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("malformed STATUS response line: %q", line)
		}
		name := m[1]
		if name == "" {
			name = m[2]
		}
		got[name] = line
	}
	return got
}

func startSharedIMAPServerOnDB(t *testing.T, rdb *resilient.ResilientDatabase, shared config.SharedMailboxesConfig) string {
	t.Helper()
	address := common.GetRandomAddress(t)
	tempDir, err := os.MkdirTemp("", "sora-test-shared-root-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,
		10,
		1,
		3,
		time.Second,
		0,
		"test-shared-root",
		rdb,
		&storage.S3Storage{},
		nil,
		errCh,
	)
	if err != nil {
		t.Fatalf("uploader.New: %v", err)
	}

	srv, err := imapsrv.New(
		context.Background(),
		"test-shared-root",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil,
		imapsrv.IMAPServerOptions{
			InsecureAuth: true,
			Config:       &config.Config{SharedMailboxes: shared},
		},
	)
	if err != nil {
		t.Fatalf("imap.New: %v", err)
	}

	go func() {
		_ = srv.Serve(address)
	}()
	time.Sleep(100 * time.Millisecond)

	t.Cleanup(func() {
		srv.Close()
		uploadWorker.Stop()
	})
	return address
}

// TestIMAP_SharedNamespaceRootNoSelect_ESearchAndNotify verifies Sora's
// hierarchy-only shared-root message policy while retaining NOTIFY tree events:
//
//   - While shared mailboxes are disabled, "Shared" is a selectable personal
//     mailbox and is included in ESEARCH and NOTIFY STATUS.
//   - Once shared mailboxes are enabled (NamespacePrefix = "Shared/"), "Shared"
//     is a \Noselect hierarchy container (SELECT and STATUS refuse it with
//     NO [CANNOT]). Neither ESEARCH IN (SUBTREE / SUBTREE-ONE / MAILBOXES /
//     SUBSCRIBED) nor NOTIFY SET STATUS (SUBTREE / SUBSCRIBED / MAILBOXES) may
//     emit ESEARCH or STATUS responses for "Shared", even when "Shared" is
//     subscribed or holds pre-existing messages.
//   - Hierarchy events (MailboxName and SubscriptionChange) still report
//     "Shared" as `* LIST (\Noselect ...) "/" "Shared"`.
func TestIMAP_SharedNamespaceRootNoSelect_ESearchAndNotify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)

	// Scenario A: Clean account where "Shared" is auto-created solely as the
	// \Noselect parent of "Shared/Team". Even with 0 messages in "Shared",
	// NOTIFY SET STATUS (SUBTREE "Shared" (MessageNew ...)) must not emit
	// * STATUS "Shared" (...).
	freshAccount := common.CreateTestAccount(t, rdb)
	enabledAddr := startSharedIMAPServerOnDB(t, rdb, config.SharedMailboxesConfig{
		Enabled:         true,
		NamespacePrefix: "Shared/",
		AllowUserCreate: true,
		DefaultRights:   "lrswipkxtea",
	})
	{
		fc, fr := esearchDialLogin(t, &common.TestServer{Address: enabledAddr}, freshAccount.Email, freshAccount.Password)
		_ = fc.SetDeadline(time.Now().Add(15 * time.Second))
		esearchCreate(t, fc, fr, "f1", "Shared/Team")
		esearchCmdOK(t, fc, fr, "f2", `SUBSCRIBE "Shared"`)
		esearchCmdOK(t, fc, fr, "f3", `SUBSCRIBE "Shared/Team"`)
		esearchAppend(t, fc, fr, "f4", "Shared/Team", "fresh-shared-team")

		for _, tc := range []struct{ tag, spec string }{
			{"fn1", `SUBTREE "Shared"`},
			{"fn2", `SUBSCRIBED`},
			{"fn3", `MAILBOXES ("Shared" "Shared/Team")`},
		} {
			got := statusMailboxes(t, esearchCmdOK(t, fc, fr, tc.tag, `NOTIFY SET STATUS (`+tc.spec+` (MessageNew MessageExpunge FlagChange))`))
			if badLine, bad := got["Shared"]; bad {
				t.Errorf("fresh account NOTIFY SET STATUS (%s ...) emitted forbidden STATUS for \\Noselect root \"Shared\": %s", tc.spec, badLine)
			}
			if _, ok := got["Shared/Team"]; !ok {
				t.Errorf("fresh account NOTIFY SET STATUS (%s ...) missing STATUS for \"Shared/Team\"; got %v", tc.spec, got)
			}
		}
		_ = fc.Close()
	}

	account := common.CreateTestAccount(t, rdb)
	const probeSubject = "shared-root-noselect-probe"

	// Scenario B, Phase 1: sharing disabled — "Shared" is a normal selectable personal mailbox.
	disabledAddr := startSharedIMAPServerOnDB(t, rdb, config.SharedMailboxesConfig{
		Enabled:         false,
		NamespacePrefix: "Shared/",
	})
	{
		conn, r := esearchDialLogin(t, &common.TestServer{Address: disabledAddr}, account.Email, account.Password)
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		esearchCreate(t, conn, r, "d1", "Shared")
		esearchCmdOK(t, conn, r, "d2", `SUBSCRIBE "Shared"`)
		esearchAppend(t, conn, r, "d3", "Shared", probeSubject)

		gotSearch := esearchMailboxes(t, esearchCmdOK(t, conn, r, "d4", `ESEARCH IN (SUBTREE "Shared") RETURN (ALL) SUBJECT "`+probeSubject+`"`))
		esearchAssertHas(t, gotSearch, "Shared")

		gotStatus := statusMailboxes(t, esearchCmdOK(t, conn, r, "d5", `NOTIFY SET STATUS (SUBTREE "Shared" (MessageNew MessageExpunge FlagChange))`))
		if _, ok := gotStatus["Shared"]; !ok {
			t.Fatalf("sharing disabled: expected initial STATUS for selectable \"Shared\", got %v", gotStatus)
		}
		_ = conn.Close()
	}

	// Scenario B, Phase 2: sharing enabled on the same database — "Shared" is now \Noselect.
	conn, r := esearchDialLogin(t, &common.TestServer{Address: enabledAddr}, account.Email, account.Password)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	esearchCreate(t, conn, r, "e1", "Shared/Team")
	esearchCmdOK(t, conn, r, "e2", `SUBSCRIBE "Shared/Team"`)
	esearchAppend(t, conn, r, "e3", "Shared/Team", probeSubject)

	// Sanity check: direct SELECT and STATUS on "Shared" are refused as \Noselect.
	if _, tagged := esearchExec(t, conn, r, "e4", `SELECT "Shared"`); !strings.HasPrefix(tagged, "e4 NO [CANNOT]") {
		t.Fatalf("SELECT \"Shared\" = %q, want NO [CANNOT]", tagged)
	}
	if _, tagged := esearchExec(t, conn, r, "e5", `STATUS "Shared" (MESSAGES)`); !strings.HasPrefix(tagged, "e5 NO [CANNOT]") {
		t.Fatalf("STATUS \"Shared\" = %q, want NO [CANNOT]", tagged)
	}

	// ESEARCH IN (...) must return only "Shared/Team" and never the \Noselect root "Shared".
	for _, tc := range []struct {
		tag   string
		scope string
	}{
		{"s1", `SUBTREE "Shared"`},
		{"s2", `SUBTREE-ONE "Shared"`},
		{"s3", `MAILBOXES ("Shared" "Shared/Team")`},
		{"s4", `SUBSCRIBED`},
	} {
		lines := esearchCmdOK(t, conn, r, tc.tag, `ESEARCH IN (`+tc.scope+`) RETURN (ALL) SUBJECT "`+probeSubject+`"`)
		got := esearchMailboxes(t, lines)
		if _, bad := got["Shared"]; bad {
			t.Errorf("ESEARCH IN (%s) emitted result for \\Noselect root \"Shared\": %v", tc.scope, lines)
		}
		if len(got) != 1 || got["Shared/Team"] == "" {
			t.Errorf("ESEARCH IN (%s) mailboxes = %v, want only Shared/Team", tc.scope, got)
		}
	}

	// NOTIFY SET STATUS must emit * STATUS "Shared/Team" (...) and never * STATUS "Shared" (...).
	for _, tc := range []struct {
		tag  string
		spec string
	}{
		{"n1", `SUBTREE "Shared"`},
		{"n2", `SUBSCRIBED`},
		{"n3", `MAILBOXES ("Shared" "Shared/Team")`},
	} {
		lines := esearchCmdOK(t, conn, r, tc.tag, `NOTIFY SET STATUS (`+tc.spec+` (MessageNew MessageExpunge FlagChange))`)
		got := statusMailboxes(t, lines)
		if badLine, bad := got["Shared"]; bad {
			t.Errorf("NOTIFY SET STATUS (%s ...) emitted forbidden STATUS for \\Noselect root \"Shared\": %s", tc.spec, badLine)
		}
		if _, ok := got["Shared/Team"]; !ok {
			t.Errorf("NOTIFY SET STATUS (%s ...) missing STATUS for \"Shared/Team\"; got %v", tc.spec, got)
		}
	}
	esearchCmdOK(t, conn, r, "n4", "NOTIFY NONE")

	// Tree events (SubscriptionChange and MailboxName) must still report * LIST (\Noselect ...) "/" "Shared".
	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, enabledAddr, account, rec.options(), "")
	defer watcher.Logout()

	notifyCmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{{
			MailboxSpec: imap.NotifyMailboxSpecSubscribed,
			Events:      []imap.NotifyEvent{imap.NotifyEventSubscriptionChange},
		}},
	})
	if err != nil {
		t.Fatalf("watcher.Notify: %v", err)
	}
	if err := notifyCmd.Wait(); err != nil {
		t.Fatalf("watcher.Notify.Wait: %v", err)
	}

	esearchCmdOK(t, conn, r, "u1", `UNSUBSCRIBE "Shared"`)
	unsubData := rec.waitList(t, "Shared", 4*time.Second)
	if !listHasAttr(unsubData, imap.MailboxAttrNoSelect) || listHasAttr(unsubData, imap.MailboxAttrSubscribed) {
		t.Errorf("UNSUBSCRIBE \"Shared\" SubscriptionChange LIST = %+v, want \\Noselect without \\Subscribed", unsubData)
	}

	esearchCmdOK(t, conn, r, "u2", `SUBSCRIBE "Shared"`)
	subData := rec.waitList(t, "Shared", 4*time.Second)
	if !listHasAttr(subData, imap.MailboxAttrNoSelect) || !listHasAttr(subData, imap.MailboxAttrSubscribed) {
		t.Errorf("SUBSCRIBE \"Shared\" SubscriptionChange LIST = %+v, want \\Noselect and \\Subscribed", subData)
	}
}
