package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tab-escaping as Dovecot's str_append_tabescaped / str_append_tabunescaped do it
// (src/lib/strescape.c), on the hierarchy levels of a version 2 subscriptions file.
func TestDovecotSubscriptionsTabEscaping(t *testing.T) {
	names := []string{"INBOX", "Work/Projects", "a\x01b/c\td", "x\ry\nz"}
	file := formatDovecotSubscriptions(names)
	assert.Equal(t, "V\t2\n\nINBOX\nWork\tProjects\na\x011b\tc\x01td\nx\x01ry\x01nz\n", file)
	assert.Equal(t, names, parseDovecotSubscriptions(file))

	// \001 0 is NUL, \001 followed by any other byte is that byte, a trailing \001 is dropped.
	assert.Equal(t, []string{"a\x00b/cq/d"}, parseDovecotSubscriptions("V\t2\n\na\x010b\tc\x01q\td\x01\n"))
}

// How Dovecot reads a subscriptions file beyond the escaping:
//   - lines come from i_stream_next_line (src/lib/istream.c), which drops the CR of a
//     CRLF line end;
//   - a name ending in the hierarchy separator loses it
//     (mailbox_list_subscription_fill_one, src/lib-storage/list/mailbox-list-subscriptions.c);
//   - an unversioned file holds storage names (index_storage_set_subscribed writes
//     box->name), whose separator is the list's: '.' for Maildir++
//     (src/lib-storage/list/mailbox-list-maildir.c), the separator the folder import
//     turns into '/'.
//
// A file written by an older sora-admin export already uses '/', and its dots stay.
func TestParseDovecotSubscriptionsLines(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		want       []string
	}{
		{"unversioned CRLF", "INBOX\r\nVendors\r\n", []string{"INBOX", "Vendors"}},
		{"version 2 CRLF", "V\t2\n\nINBOX\r\nWork\tProjects\r\n", []string{"INBOX", "Work/Projects"}},
		{"version 2 trailing separator", "V\t2\n\nWork\t\n\t\n", []string{"Work"}},
		{"unversioned Maildir++", "INBOX\nWork.Projects\nDonn&AOk-es.Q1\nArchive.\n.\n", []string{"INBOX", "Work/Projects", "Donn&AOk-es/Q1", "Archive"}},
		{"older sora-admin export", "V\t2\nWork/Projects\nv1.2\n", []string{"Work/Projects", "v1.2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseDovecotSubscriptions(tc.file))
		})
	}
}
