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
