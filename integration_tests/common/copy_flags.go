//go:build integration

package common

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

// SieveFlagsBySubject maps each mailbox of accountID that holds a live message with
// the given subject to that copy's flags, lower-cased and sorted, with the RFC 9979
// attachment keyword delivery adds to every message left out; a copy without one
// fails the test. A test that delivers one message into several mailboxes reads the
// flags each copy was stored with.
func SieveFlagsBySubject(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, subject string) map[string][]string {
	t.Helper()
	rows, err := rdb.QueryWithRetry(context.Background(), `
		SELECT mb.name, ms.flags, ms.custom_flags
		FROM messages m
		JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE mb.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL`,
		accountID, subject)
	if err != nil {
		t.Fatalf("find message %q: %v", subject, err)
	}
	defer rows.Close()
	copies := make(map[string][]string)
	for rows.Next() {
		var mailbox string
		var bits int
		var customJSON []byte
		if err := rows.Scan(&mailbox, &bits, &customJSON); err != nil {
			t.Fatalf("scan message %q: %v", subject, err)
		}
		var custom []string
		if err := json.Unmarshal(customJSON, &custom); err != nil {
			t.Fatalf("custom flags %q: %v", customJSON, err)
		}
		flags := []string{}
		for _, f := range db.BitwiseToFlags(bits) {
			flags = append(flags, strings.ToLower(string(f)))
		}
		attachmentKeywords := 0
		for _, f := range custom {
			if f = strings.ToLower(f); f != "$hasattachment" && f != "$hasnoattachment" {
				flags = append(flags, f)
			} else {
				attachmentKeywords++
			}
		}
		// Every copy is stored with the attachment keyword, whatever its own flags.
		if attachmentKeywords != 1 {
			t.Errorf("copy of %q in %s has keywords %v, want exactly one RFC 9979 attachment keyword", subject, mailbox, custom)
		}
		slices.Sort(flags)
		copies[mailbox] = flags
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("find message %q: %v", subject, err)
	}
	return copies
}
