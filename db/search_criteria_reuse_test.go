package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/require"
)

func TestSearchCriteriaRemainsReusable(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("criteria_reuse_%d@example.com", stamp), "password")
	mailboxID := seedDenseMailbox(t, database, accountID, fmt.Sprintf("Reuse_%d", stamp), 3)
	newCriteria := func() *imap.SearchCriteria {
		return &imap.SearchCriteria{
			SeqNum: []imap.SeqSet{imap.SeqSetNum(1, 2)},
			Not:    []imap.SearchCriteria{{SeqNum: []imap.SeqSet{imap.SeqSetNum(3)}}},
			Or: [][2]imap.SearchCriteria{{
				{SeqNum: []imap.SeqSet{imap.SeqSetNum(1)}},
				{UID: []imap.UIDSet{imap.UIDSetNum(2)}},
			}},
		}
	}
	for _, thread := range []bool{false, true} {
		t.Run(fmt.Sprintf("thread=%v", thread), func(t *testing.T) {
			criteria := newCriteria()
			if thread {
				_, err := database.GetMessagesForThreading(ctx, mailboxID, accountID, criteria, true, false, 10)
				require.NoError(t, err)
			} else {
				_, err := database.SearchMessagesWithCriteria(ctx, mailboxID, accountID, criteria, 0, 3)
				require.NoError(t, err)
			}
			require.Equal(t, newCriteria(), criteria, "search must not replace caller-owned sequence sets with mailbox-specific UIDs")
		})
	}
}
