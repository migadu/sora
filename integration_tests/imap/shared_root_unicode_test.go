//go:build integration

package imap_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIMAP_SharedRootUnicodeCaseRules(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	t.Run("personal_equalfold_names", func(t *testing.T) {
		for _, tc := range []struct {
			prefix       string
			personalRoot string
		}{
			{"Shared/", "ſhared"},
			{"ΑΣ/", "ας"},
		} {
			t.Run(tc.prefix, func(t *testing.T) {
				cfg := config.SharedMailboxesConfig{
					Enabled:         true,
					NamespacePrefix: tc.prefix,
					AllowUserCreate: true,
					DefaultRights:   "lrswipkxtea",
				}
				require.False(t, cfg.IsNamespaceRoot(tc.personalRoot))
				require.False(t, cfg.InNamespace(tc.personalRoot))

				srv, account1 := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{SharedMailboxes: &cfg})
				defer srv.Close()

				// 1. Direct CREATE of personal folder whose name EqualFolds to the shared prefix.
				t.Run("direct_create", func(t *testing.T) {
					c1, err := imapclient.DialInsecure(srv.Address, nil)
					require.NoError(t, err)
					defer c1.Logout()
					require.NoError(t, c1.Login(account1.Email, account1.Password).Wait())
					_, err = c1.Enable(imap.CapIMAP4rev2).Wait()
					require.NoError(t, err)

					require.NoError(t, c1.Create(tc.personalRoot, nil).Wait(),
						"personal mailbox %q under prefix %q must not be refused as shared root", tc.personalRoot, tc.prefix)

					var isShared bool
					require.NoError(t, srv.ResilientDB.QueryRowWithRetry(
						context.Background(),
						`SELECT is_shared FROM mailboxes m JOIN credentials c ON c.account_id = m.account_id AND c.primary_identity WHERE m.name = $1 AND c.address = $2 AND m.deleted_at IS NULL`,
						tc.personalRoot, account1.Email,
					).Scan(&isShared))
					assert.False(t, isShared, "%q must be a personal mailbox", tc.personalRoot)
				})

				// 2. Auto-created parent via CREATE "<personalRoot>/Child" + APPEND + SELECT/STATUS/LIST/NOTIFY.
				t.Run("auto_created_parent_and_access", func(t *testing.T) {
					account2 := common.CreateTestAccount(t, srv.ResilientDB)
					account2ID, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account2.Email)
					require.NoError(t, err)

					c2, err := imapclient.DialInsecure(srv.Address, nil)
					require.NoError(t, err)
					defer c2.Logout()
					require.NoError(t, c2.Login(account2.Email, account2.Password).Wait())
					_, err = c2.Enable(imap.CapIMAP4rev2).Wait()
					require.NoError(t, err)

					require.NoError(t, c2.Create(tc.personalRoot+"/Child", nil).Wait())

					literal := "From: sender@example.com\r\nSubject: personal-probe\r\n\r\nbody\r\n"
					appendCmd := c2.Append(tc.personalRoot, int64(len(literal)), nil)
					_, err = appendCmd.Write([]byte(literal))
					require.NoError(t, err)
					require.NoError(t, appendCmd.Close())
					_, err = appendCmd.Wait()
					require.NoError(t, err, "APPEND to personal parent %q must succeed", tc.personalRoot)
					require.Equal(t, 1, liveMessagesIn(t, srv, account2ID, tc.personalRoot))

					selData, err := c2.Select(tc.personalRoot, nil).Wait()
					if assert.NoError(t, err, "SELECT %q must succeed so stored personal mail is readable", tc.personalRoot) {
						assert.Equal(t, uint32(1), selData.NumMessages)
					}

					stData, err := c2.Status(tc.personalRoot, &imap.StatusOptions{NumMessages: true}).Wait()
					if assert.NoError(t, err, "STATUS %q must succeed", tc.personalRoot) && stData.NumMessages != nil {
						assert.Equal(t, uint32(1), *stData.NumMessages)
					}

					listed, err := c2.List("", tc.personalRoot, &imap.ListOptions{
						ReturnStatus: &imap.StatusOptions{NumMessages: true},
					}).Collect()
					require.NoError(t, err)
					if assert.Len(t, listed, 1) {
						assert.False(t, listHasAttr(listed[0], imap.MailboxAttrNoSelect),
							"LIST must not mark personal mailbox %q \\Noselect: %+v", tc.personalRoot, listed[0])
						if assert.NotNil(t, listed[0].Status, "LIST-STATUS must emit STATUS for %q", tc.personalRoot) && listed[0].Status.NumMessages != nil {
							assert.Equal(t, uint32(1), *listed[0].Status.NumMessages)
						}
					}

					rec := newNotifyRecorder()
					watcher := notifyLoginAndSelect(t, srv.Address, account2, rec.options(), "")
					defer watcher.Logout()
					_, err = watcher.Enable(imap.CapIMAP4rev2).Wait()
					require.NoError(t, err)

					notifyCmd, err := watcher.Notify(&imap.NotifyOptions{
						Items: []imap.NotifyItem{{
							Mailboxes: []string{tc.personalRoot},
							Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
						}},
					})
					require.NoError(t, err)
					require.NoError(t, notifyCmd.Wait())

					require.NoError(t, c2.Delete(tc.personalRoot+"/Child").Wait())
					ev := rec.waitList(t, tc.personalRoot, 4*time.Second)
					assert.False(t, listHasAttr(ev, imap.MailboxAttrNoSelect),
						"NOTIFY LIST must not mark personal mailbox %q \\Noselect: %+v", tc.personalRoot, ev)
				})
			})
		}
	})

	t.Run("dotted_i_shared_root", func(t *testing.T) {
		t.Run("allow_user_create_true_refuses_direct_root_create", func(t *testing.T) {
			cfg := config.SharedMailboxesConfig{
				Enabled:         true,
				NamespacePrefix: "İx/",
				AllowUserCreate: true,
				DefaultRights:   "lrswipkxtea",
			}
			require.True(t, cfg.IsNamespaceRoot("ix"))

			srv, owner := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{SharedMailboxes: &cfg})
			defer srv.Close()

			c, err := imapclient.DialInsecure(srv.Address, nil)
			require.NoError(t, err)
			defer c.Logout()
			require.NoError(t, c.Login(owner.Email, owner.Password).Wait())

			requireResponseCode(t, c.Create("ix", nil).Wait(), imap.ResponseCodeCannot, "CREATE shared root \"ix\" under \"İx/\"")
		})

		t.Run("allow_user_create_false_enforces_root_and_top_level_policy", func(t *testing.T) {
			cfg := config.SharedMailboxesConfig{
				Enabled:         true,
				NamespacePrefix: "İx/",
				AllowUserCreate: false,
				DefaultRights:   "lrswipkxtea",
			}
			srv, owner := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{SharedMailboxes: &cfg})
			defer srv.Close()

			c, err := imapclient.DialInsecure(srv.Address, nil)
			require.NoError(t, err)
			defer c.Logout()
			require.NoError(t, c.Login(owner.Email, owner.Password).Wait())

			// Direct root CREATE is [CANNOT], not [NOPERM].
			assertResponseCode(t, c.Create("ix", nil).Wait(), imap.ResponseCodeCannot, "CREATE shared root \"ix\"")

			// Seed an administrator-created shared mailbox "ix/First" (auto-creating container "ix").
			adminCfg := &config.Config{SharedMailboxes: config.SharedMailboxesConfig{
				Enabled:         true,
				NamespacePrefix: "İx/",
				AllowUserCreate: true,
				DefaultRights:   "lrswipkxtea",
			}}
			adminCtx := context.WithValue(context.Background(), consts.ConfigContextKey, adminCfg)
			ownerID, err := srv.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
			require.NoError(t, err)
			require.NoError(t, srv.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, "ix/First"))

			// Extending the existing shared mailbox "ix/First" is permitted.
			require.NoError(t, c.Create("ix/First/Sub", nil).Wait())

			// Creating a new top-level shared mailbox "ix/Second" (or renaming into one) must be
			// refused with [NOPERM], not authorized by the auto-created "ix" container row.
			if err := c.Create("ix/Second", nil).Wait(); err == nil {
				t.Errorf("CREATE new top-level shared mailbox \"ix/Second\" succeeded with allow_user_create=false, want NO [NOPERM]")
				_ = c.Delete("ix/Second").Wait()
			} else {
				assertResponseCode(t, err, imap.ResponseCodeNoPerm, "CREATE new top-level shared mailbox \"ix/Second\"")
			}
			if err := c.Rename("ix/First/Sub", "ix/RenamedTop", nil).Wait(); err == nil {
				t.Errorf("RENAME to new top-level shared mailbox \"ix/RenamedTop\" succeeded with allow_user_create=false, want NO [NOPERM]")
				_ = c.Delete("ix/RenamedTop").Wait()
				require.NoError(t, c.Create("ix/First/Sub", nil).Wait())
			} else {
				assertResponseCode(t, err, imap.ResponseCodeNoPerm, "RENAME to new top-level shared mailbox \"ix/RenamedTop\"")
			}

			// Container "ix" must remain non-selectable in SELECT, STATUS, LIST, LIST-STATUS, and NOTIFY.
			_, err = c.Select("ix", nil).Wait()
			assertResponseCode(t, err, imap.ResponseCodeCannot, "SELECT shared root \"ix\"")
			_, err = c.Select("INBOX", nil).Wait()
			require.NoError(t, err)

			_, err = c.Status("ix", &imap.StatusOptions{NumMessages: true}).Wait()
			assertResponseCode(t, err, imap.ResponseCodeCannot, "STATUS shared root \"ix\"")

			listed, err := c.List("", "ix", &imap.ListOptions{
				ReturnStatus: &imap.StatusOptions{NumMessages: true},
			}).Collect()
			require.NoError(t, err)
			if assert.Len(t, listed, 1) {
				assert.True(t, listHasAttr(listed[0], imap.MailboxAttrNoSelect),
					"LIST must mark shared root \"ix\" \\Noselect: %+v", listed[0])
				assert.Nil(t, listed[0].Status, "LIST-STATUS must omit STATUS for \\Noselect shared root \"ix\"")
			}

			rec := newNotifyRecorder()
			watcher := notifyLoginAndSelect(t, srv.Address, owner, rec.options(), "")
			defer watcher.Logout()

			notifyCmd, err := watcher.Notify(&imap.NotifyOptions{
				Items: []imap.NotifyItem{{
					Mailboxes: []string{"ix"},
					Events:    []imap.NotifyEvent{imap.NotifyEventMailboxName},
				}},
			})
			require.NoError(t, err)
			require.NoError(t, notifyCmd.Wait())

			require.NoError(t, c.Delete("ix/First/Sub").Wait())
			require.NoError(t, c.Delete("ix/First").Wait())
			ev := rec.waitList(t, "ix", 4*time.Second)
			assert.True(t, listHasAttr(ev, imap.MailboxAttrNoSelect),
				"NOTIFY LIST must mark shared root \"ix\" \\Noselect even after last child is deleted: %+v", ev)
		})
	})
}

func assertResponseCode(t *testing.T, err error, code imap.ResponseCode, what string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: succeeded, want NO [%s]", what, code)
		return
	}
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != code {
		t.Errorf("%s: got %v, want NO [%s]", what, err, code)
	}
}
