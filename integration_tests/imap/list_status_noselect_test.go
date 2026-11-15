//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_ListStatusExcludesSharedRootAndRetainsNoSelect verifies RFC 5819 §2 /
// RFC 9051 §6.3.9.2 and shared-namespace root invariants:
//   - LIST ... RETURN (STATUS (...)) MUST NOT send a STATUS response for a
//     mailbox listed with \Noselect (such as the auto-created "Shared" root).
//   - After the last child under "Shared" is deleted, LIST still marks "Shared"
//     with \Noselect (matching SELECT, which refuses it with NO [CANNOT]) and
//     still omits * STATUS for it.
//   - Direct STATUS on the shared-namespace root fails with NO [CANNOT] and
//     emits no * STATUS line, while personal parents above a multi-segment
//     shared prefix ("Public" for "Public/Rooms/") remain selectable and
//     answer STATUS normally.
func TestIMAP_ListStatusExcludesSharedRootAndRetainsNoSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	t.Run("default Shared prefix", func(t *testing.T) {
		c := dialDisabledCaps(t, nil, false)

		// Even before any shared child exists, direct STATUS on "Shared" is
		// refused with NO [CANNOT] (matching SELECT "Shared").
		resp, tagged := statusDeletedDo(c, `STATUS "Shared" (MESSAGES DELETED)`)
		if strings.Contains(resp, "* STATUS ") || !strings.Contains(tagged, " NO [CANNOT] ") {
			t.Errorf(`STATUS "Shared" before child create: want NO [CANNOT] without * STATUS, got:\n%s`, resp)
		}

		// Creating "Shared/Team" auto-creates the "Shared" parent row.
		c.mustOK(`CREATE "Shared/Team"`)

		// LIST "" "*" RETURN (STATUS ...) must list "Shared" with \Noselect and
		// MUST NOT emit * STATUS for "Shared", while emitting * STATUS for
		// selectable mailboxes ("INBOX", "Shared/Team").
		resp = c.mustOK(`LIST "" "*" RETURN (STATUS (MESSAGES DELETED))`)
		if !hasListLineWithAttr(resp, `"Shared"`, `\Noselect`) {
			t.Errorf(`LIST "" "*": want "Shared" listed with \Noselect, got:\n%s`, resp)
		}
		if hasStatusLineForMailbox(resp, "Shared") {
			t.Errorf(`LIST "" "*" RETURN (STATUS ...): must NOT emit * STATUS for \Noselect "Shared", got:\n%s`, resp)
		}
		if !hasStatusLineForMailbox(resp, "Shared/Team") {
			t.Errorf(`LIST "" "*" RETURN (STATUS ...): want * STATUS for "Shared/Team", got:\n%s`, resp)
		}
		if !hasStatusLineForMailbox(resp, "INBOX") {
			t.Errorf(`LIST "" "*" RETURN (STATUS ...): want * STATUS for INBOX, got:\n%s`, resp)
		}

		// Direct STATUS on the auto-created "Shared" row (any case) must also
		// fail with NO [CANNOT] and no * STATUS line.
		for _, cmd := range []string{
			`STATUS "Shared" (MESSAGES DELETED)`,
			`STATUS "shared" (MESSAGES)`,
		} {
			resp, tagged = statusDeletedDo(c, cmd)
			if strings.Contains(resp, "* STATUS ") || !strings.Contains(tagged, " NO [CANNOT] ") {
				t.Errorf("%s: want NO [CANNOT] without * STATUS, got:\n%s", cmd, resp)
			}
		}

		// Even if subscribed, a \Noselect entry must not emit * STATUS in
		// LIST (SUBSCRIBED) ... RETURN (STATUS ...).
		c.mustOK(`SUBSCRIBE "Shared"`)
		c.mustOK(`SUBSCRIBE "Shared/Team"`)
		resp = c.mustOK(`LIST (SUBSCRIBED) "" "*" RETURN (STATUS (MESSAGES DELETED))`)
		if !hasListLineWithAttr(resp, `"Shared"`, `\Noselect`) {
			t.Errorf(`LIST (SUBSCRIBED): want "Shared" listed with \Noselect, got:\n%s`, resp)
		}
		if hasStatusLineForMailbox(resp, "Shared") {
			t.Errorf(`LIST (SUBSCRIBED) RETURN (STATUS ...): must NOT emit * STATUS for \Noselect "Shared", got:\n%s`, resp)
		}
		if !hasStatusLineForMailbox(resp, "Shared/Team") {
			t.Errorf(`LIST (SUBSCRIBED) RETURN (STATUS ...): want * STATUS for "Shared/Team", got:\n%s`, resp)
		}

		// Delete the last child under "Shared": the remaining "Shared" row has
		// HasChildren=false, yet SELECT still refuses it with NO [CANNOT], so
		// LIST must retain \Noselect and omit * STATUS, and direct STATUS must
		// still return NO [CANNOT].
		c.mustOK(`DELETE "Shared/Team"`)

		resp = c.mustOK(`LIST "" "Shared" RETURN (STATUS (MESSAGES DELETED))`)
		if !hasListLineWithAttr(resp, `"Shared"`, `\Noselect`) {
			t.Errorf(`LIST "" "Shared" after child delete: want \Noselect retained on "Shared", got:\n%s`, resp)
		}
		if hasStatusLineForMailbox(resp, "Shared") {
			t.Errorf(`LIST "" "Shared" RETURN (STATUS ...) after child delete: must NOT emit * STATUS for "Shared", got:\n%s`, resp)
		}

		resp, tagged = statusDeletedDo(c, `STATUS "Shared" (MESSAGES DELETED)`)
		if strings.Contains(resp, "* STATUS ") || !strings.Contains(tagged, " NO [CANNOT] ") {
			t.Errorf(`STATUS "Shared" after child delete: want NO [CANNOT] without * STATUS, got:\n%s`, resp)
		}
	})

	t.Run("multi-segment prefix Public/Rooms/", func(t *testing.T) {
		c := dialDisabledCaps(t, func(o *imapserver.IMAPServerOptions) {
			o.Config.SharedMailboxes.NamespacePrefix = "Public/Rooms/"
		}, false)

		c.mustOK(`CREATE "Public/Rooms/Lobby"`)

		resp := c.mustOK(`LIST "" "*" RETURN (STATUS (MESSAGES))`)
		if !hasListLineWithAttr(resp, `"Public/Rooms"`, `\Noselect`) {
			t.Errorf(`want "Public/Rooms" marked \Noselect, got:\n%s`, resp)
		}
		if hasStatusLineForMailbox(resp, "Public/Rooms") {
			t.Errorf(`must NOT emit * STATUS for \Noselect "Public/Rooms", got:\n%s`, resp)
		}
		if !hasStatusLineForMailbox(resp, "Public") {
			t.Errorf(`want * STATUS for personal ancestor "Public", got:\n%s`, resp)
		}
		if !hasStatusLineForMailbox(resp, "Public/Rooms/Lobby") {
			t.Errorf(`want * STATUS for "Public/Rooms/Lobby", got:\n%s`, resp)
		}

		resp, tagged := statusDeletedDo(c, `STATUS "Public/Rooms" (MESSAGES)`)
		if strings.Contains(resp, "* STATUS ") || !strings.Contains(tagged, " NO [CANNOT] ") {
			t.Errorf(`STATUS "Public/Rooms": want NO [CANNOT] without * STATUS, got:\n%s`, resp)
		}
		if resp = c.mustOK(`STATUS "Public" (MESSAGES)`); !hasStatusLineForMailbox(resp, "Public") {
			t.Errorf(`STATUS "Public": want * STATUS for personal ancestor, got:\n%s`, resp)
		}
	})

	t.Run("shared mailboxes disabled allows personal Shared", func(t *testing.T) {
		c := dialDisabledCaps(t, func(o *imapserver.IMAPServerOptions) {
			o.Config = &config.Config{
				SharedMailboxes: config.SharedMailboxesConfig{Enabled: false},
			}
		}, false)

		c.mustOK(`CREATE "Shared"`)
		resp := c.mustOK(`STATUS "Shared" (MESSAGES DELETED)`)
		if !hasStatusLineForMailbox(resp, "Shared") {
			t.Errorf(`personal "Shared" with sharing disabled: want * STATUS, got:\n%s`, resp)
		}
		resp = c.mustOK(`LIST "" "Shared" RETURN (STATUS (MESSAGES DELETED))`)
		if hasListLineWithAttr(resp, `"Shared"`, `\Noselect`) {
			t.Errorf(`personal "Shared" with sharing disabled: must NOT be \Noselect, got:\n%s`, resp)
		}
		if !hasStatusLineForMailbox(resp, "Shared") {
			t.Errorf(`personal "Shared" with sharing disabled: want * STATUS in LIST-STATUS, got:\n%s`, resp)
		}
	})
}

// TestIMAP_ListStatusExcludesUnsubscribedRecursiveMatchParents verifies RFC 5819
// §2 & §3.2 / RFC 9051 §6.3.9.2:
//   - "STATUS responses MUST only be returned for mailboxes that match the
//     selection options."
//   - "If the server lists a mailbox with the \Noselect or \NonExistent
//     attribute, the server MUST NOT send a STATUS response for that mailbox."
func TestIMAP_ListStatusExcludesUnsubscribedRecursiveMatchParents(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	c := dialDisabledCaps(t, nil, false)

	c.mustOK(`CREATE "Projects"`)
	c.mustOK(`CREATE "Projects/2026"`)
	c.mustOK(`CREATE "Notes"`)
	c.mustOK(`SUBSCRIBE "Projects/2026"`)
	c.mustOK(`SUBSCRIBE "Notes"`)
	c.mustOK(`SUBSCRIBE "Ghost/Child"`) // non-existent hierarchy with subscribed child
	c.mustOK(`SUBSCRIBE "Gone"`)        // non-existent subscribed leaf

	// Top-level "%" with (SUBSCRIBED RECURSIVEMATCH):
	// - "Projects" is unsubscribed, listed only because "Projects/2026" is subscribed
	//   -> carries CHILDINFO ("SUBSCRIBED"), MUST NOT get * STATUS.
	// - "Ghost" is \NonExistent with CHILDINFO ("SUBSCRIBED") -> MUST NOT get * STATUS.
	// - "Gone" is \NonExistent \Subscribed -> MUST NOT get * STATUS.
	// - "Notes" is live and subscribed -> MUST get * STATUS.
	resp := c.mustOK(`LIST (SUBSCRIBED RECURSIVEMATCH) "" "%" RETURN (STATUS (MESSAGES DELETED))`)
	if !strings.Contains(resp, `"Projects" (CHILDINFO ("SUBSCRIBED"))`) {
		t.Errorf(`want "Projects" with (CHILDINFO ("SUBSCRIBED")), got:\n%s`, resp)
	}
	if hasStatusLineForMailbox(resp, "Projects") {
		t.Errorf(`must NOT emit * STATUS for unsubscribed RECURSIVEMATCH parent "Projects", got:\n%s`, resp)
	}
	if hasStatusLineForMailbox(resp, "Ghost") {
		t.Errorf(`must NOT emit * STATUS for \NonExistent parent "Ghost", got:\n%s`, resp)
	}
	if hasStatusLineForMailbox(resp, "Gone") {
		t.Errorf(`must NOT emit * STATUS for \NonExistent subscribed "Gone", got:\n%s`, resp)
	}
	if !hasStatusLineForMailbox(resp, "Notes") {
		t.Errorf(`want * STATUS for subscribed "Notes", got:\n%s`, resp)
	}

	// Wildcard "*" with (SUBSCRIBED RECURSIVEMATCH):
	// "Projects" still did not match SUBSCRIBED (no * STATUS), whereas
	// "Projects/2026" and "Notes" matched SUBSCRIBED and DO get * STATUS.
	resp = c.mustOK(`LIST (SUBSCRIBED RECURSIVEMATCH) "" "*" RETURN (STATUS (MESSAGES DELETED))`)
	if hasStatusLineForMailbox(resp, "Projects") {
		t.Errorf(`"*" must NOT emit * STATUS for unsubscribed parent "Projects", got:\n%s`, resp)
	}
	if !hasStatusLineForMailbox(resp, "Projects/2026") {
		t.Errorf(`"*" want * STATUS for subscribed child "Projects/2026", got:\n%s`, resp)
	}
	if !hasStatusLineForMailbox(resp, "Notes") {
		t.Errorf(`"*" want * STATUS for subscribed "Notes", got:\n%s`, resp)
	}

	// Once "Projects" itself is subscribed, it matches SUBSCRIBED (while still
	// carrying CHILDINFO ("SUBSCRIBED")), so * STATUS "Projects" MUST be emitted.
	c.mustOK(`SUBSCRIBE "Projects"`)
	resp = c.mustOK(`LIST (SUBSCRIBED RECURSIVEMATCH) "" "%" RETURN (STATUS (MESSAGES DELETED))`)
	if !strings.Contains(resp, `"Projects" (CHILDINFO ("SUBSCRIBED"))`) {
		t.Errorf(`subscribed "Projects" should still carry CHILDINFO ("SUBSCRIBED"), got:\n%s`, resp)
	}
	if !hasStatusLineForMailbox(resp, "Projects") {
		t.Errorf(`subscribed "Projects" matches SUBSCRIBED and MUST get * STATUS, got:\n%s`, resp)
	}
}

func hasListLineWithAttr(resp, quotedMailbox, attr string) bool {
	attrLower := strings.ToLower(attr)
	for _, line := range strings.Split(resp, "\r\n") {
		if !strings.HasPrefix(line, "* LIST (") {
			continue
		}
		if !strings.Contains(line, " "+quotedMailbox) {
			continue
		}
		attrsPart, _, ok := strings.Cut(strings.TrimPrefix(line, "* LIST ("), ")")
		if !ok {
			continue
		}
		for _, tok := range strings.Fields(attrsPart) {
			if strings.ToLower(tok) == attrLower {
				return true
			}
		}
	}
	return false
}

func hasStatusLineForMailbox(resp, mailbox string) bool {
	quotedPrefix := `* STATUS "` + mailbox + `" (`
	atomPrefix := `* STATUS ` + mailbox + ` (`
	for _, line := range strings.Split(resp, "\r\n") {
		if strings.HasPrefix(line, quotedPrefix) || strings.HasPrefix(line, atomPrefix) {
			return true
		}
	}
	return false
}
