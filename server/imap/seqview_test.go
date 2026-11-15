package imap

import (
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/stretchr/testify/require"
)

// newTestSeqView returns the view of a session whose client was told about n
// messages, after queue has queued updates the client has not been sent, leaving
// serverCount messages in the server view.
func newTestSeqView(t *testing.T, n, serverCount uint32, queue func(*imapserver.MailboxTracker)) seqView {
	t.Helper()
	mbox := imapserver.NewMailboxTracker(n)
	st := mbox.NewSession()
	t.Cleanup(st.Close)
	if queue != nil {
		queue(mbox)
	}
	return seqView{tracker: st, modSeq: 1, serverCount: serverCount, direct: st.QueuedUpdates() == 0}
}

func TestSeqViewDirect(t *testing.T) {
	v := newTestSeqView(t, 5, 5, nil)
	require.True(t, v.direct)

	require.Equal(t, imap.SeqSet{{Start: 2, Stop: 3}}, v.decode(imap.SeqSet{{Start: 2, Stop: 3}}))
	// "*", and a range past the last message, end at the client's last message, never
	// at a "*" the database would resolve against its own view.
	require.Equal(t, imap.SeqSet{{Start: 1, Stop: 5}}, v.decode(imap.SeqSet{{Start: 1, Stop: 0}}))
	require.Equal(t, imap.SeqSet{{Start: 4, Stop: 5}}, v.decode(imap.SeqSet{{Start: 4, Stop: 9}}))
	require.Equal(t, imap.SeqSet{{Start: 5, Stop: 5}}, v.decode(imap.SeqSet{{Start: 0, Stop: 0}}))
	// Past the last message names nothing.
	require.Empty(t, v.decode(imap.SeqSet{{Start: 6, Stop: 9}}))

	require.Equal(t, uint32(5), v.encode(5))
	require.Zero(t, v.encode(6), "a message past the view has no client number")
}

func TestSeqViewPendingExpungesAndExists(t *testing.T) {
	// The client knows UIDs 1..5 as 1..5. The poll queued the expunges of UIDs 2 and
	// 4 (numbered 4 then 2, top-down) and an EXISTS for UID 6: the server view is
	// UIDs 1,3,5,6 and none of it has been sent.
	v := newTestSeqView(t, 5, 4, func(m *imapserver.MailboxTracker) {
		require.NoError(t, m.QueueExpunge(4, 4))
		require.NoError(t, m.QueueExpunge(2, 2))
		require.NoError(t, m.QueueNumMessages(4))
	})
	require.False(t, v.direct)
	require.Equal(t, uint32(5), v.clientCount())

	// Server view 1..4 (UIDs 1,3,5,6) is the client's 1, 3, 5 and none.
	for server, client := range map[uint32]uint32{1: 1, 2: 3, 3: 5, 4: 0, 5: 0} {
		require.Equalf(t, client, v.encode(server), "server %d", server)
	}

	cases := []struct {
		name string
		in   imap.SeqSet
		want imap.SeqSet
	}{
		{"a live message", imap.SeqSet{{Start: 3, Stop: 3}}, imap.SeqSet{{Start: 2, Stop: 2}}},
		{"an expunged message names nothing", imap.SeqSet{{Start: 2, Stop: 2}}, imap.SeqSet{}},
		{"a range drops the expunged", imap.SeqSet{{Start: 2, Stop: 4}}, imap.SeqSet{{Start: 2, Stop: 2}}},
		{"star is the client's last, not the unannounced one", imap.SeqSet{{Start: 1, Stop: 0}}, imap.SeqSet{{Start: 1, Stop: 3}}},
		{"reversed", imap.SeqSet{{Start: 5, Stop: 3}}, imap.SeqSet{{Start: 2, Stop: 3}}},
		{"past the client's last", imap.SeqSet{{Start: 6, Stop: 6}}, imap.SeqSet{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, v.decode(tc.in))
		})
	}
}

func TestSeqViewDecodeCriteria(t *testing.T) {
	v := newTestSeqView(t, 3, 2, func(m *imapserver.MailboxTracker) {
		require.NoError(t, m.QueueExpunge(1, 1))
	})
	criteria := &imap.SearchCriteria{
		SeqNum: []imap.SeqSet{{{Start: 1, Stop: 1}}, {{Start: 2, Stop: 3}}},
		UID:    []imap.UIDSet{{{Start: 7, Stop: 9}}},
		Not:    []imap.SearchCriteria{{SeqNum: []imap.SeqSet{{{Start: 3, Stop: 3}}}}},
	}
	got := v.decodeCriteria(criteria)

	// The client's 1 is gone: an empty UID set, which matches nothing.
	require.Equal(t, []imap.SeqSet{{{Start: 1, Stop: 2}}}, got.SeqNum)
	require.Equal(t, []imap.UIDSet{{{Start: 7, Stop: 9}}, {}}, got.UID)
	require.Equal(t, []imap.SeqSet{{{Start: 2, Stop: 2}}}, got.Not[0].SeqNum)
	// The caller's criteria are left as they were.
	require.Equal(t, []imap.SeqSet{{{Start: 1, Stop: 1}}, {{Start: 2, Stop: 3}}}, criteria.SeqNum)
	require.Len(t, criteria.UID, 1)
}
