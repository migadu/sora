//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
)

func TestNotifySharedParentMatchesList(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, tc := range []struct {
		name, root string
		enabled    bool
	}{
		{"default", "Shared", true}, {"multilevel", "Public/Teams", true}, {"disabled", "Shared", false},
	} {
		for _, subtree := range []bool{false, true} {
			name := "mailboxes"
			if subtree {
				name = "subtree"
			}
			t.Run(tc.name+"-"+name, func(t *testing.T) {
				srv, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{SharedMailboxes: &config.SharedMailboxesConfig{Enabled: tc.enabled, NamespacePrefix: tc.root + "/", AllowUserCreate: true, DefaultRights: "lrswipkxtea"}})
				defer srv.Close()
				other := notifyLoginAndSelect(t, srv.Address, account, nil, "")
				defer other.Logout()
				if err := other.Create(tc.root+"/Seed", nil).Wait(); err != nil {
					t.Fatal(err)
				}
				rec := newNotifyRecorder()
				watcher := notifyLoginAndSelect(t, srv.Address, account, rec.options(), "")
				defer watcher.Logout()
				listed, err := watcher.List("", tc.root, nil).Collect()
				if err != nil {
					t.Fatal(err)
				}
				if len(listed) != 1 || listHasAttr(listed[0], imap.MailboxAttrNoSelect) != tc.enabled {
					t.Fatalf("LIST root: %+v", listed)
				}
				cmd, err := watcher.Notify(&imap.NotifyOptions{Items: []imap.NotifyItem{{Mailboxes: []string{tc.root}, Subtree: subtree, Events: []imap.NotifyEvent{imap.NotifyEventMailboxName}}}})
				if err != nil {
					t.Fatal(err)
				}
				if err = cmd.Wait(); err != nil {
					t.Fatal(err)
				}
				for _, action := range []string{"create", "delete", "delete_last_child"} {
					switch action {
					case "create":
						err = other.Create(tc.root+"/Child", nil).Wait()
					case "delete":
						err = other.Delete(tc.root + "/Child").Wait()
					case "delete_last_child":
						err = other.Delete(tc.root + "/Seed").Wait()
					}
					if err != nil {
						t.Fatal(err)
					}
					data := rec.waitList(t, tc.root, 4*time.Second)
					if listHasAttr(data, imap.MailboxAttrNonExistent) {
						t.Errorf("%s root is accessible in LIST but NOTIFY says nonexistent: %+v", action, data)
					}
					if listHasAttr(data, imap.MailboxAttrNoSelect) != tc.enabled {
						t.Errorf("%s root loses LIST NoSelect in NOTIFY: %+v", action, data)
					}
					if action == "delete_last_child" && !listHasAttr(data, imap.MailboxAttrHasNoChildren) {
						t.Errorf("last child: %+v", data)
					}
				}
			})
		}
	}
}
