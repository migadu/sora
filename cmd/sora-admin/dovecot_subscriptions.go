package main

import (
	"strings"

	"github.com/migadu/sora/consts"
)

// Dovecot's subscriptions file, as src/lib-storage/list/subscription-file.c reads and
// writes it. A version 2 file starts with exactly dovecotSubscriptionsV2Header; each
// line after it is one mailbox name whose hierarchy levels are joined with TAB, each
// level tab-escaped (str_append_tabescaped). A file without that header is the old
// unversioned format, one storage name per line (index_storage_set_subscribed writes
// box->name), its levels joined with the mailbox list's separator: '.' for Maildir++
// (src/lib-storage/list/mailbox-list-maildir.c).
const dovecotSubscriptionsV2Header = "V\t2\n\n"

// soraSubscriptionsHeader is what sora-admin export wrote before it followed Dovecot's
// format: the version line with one newline, then '/'-separated names. Dovecot reads
// such a file as unversioned; the importer reads it as sora-admin meant it.
const soraSubscriptionsHeader = "V\t2\n"

// parseDovecotSubscriptions returns the mailbox names in a subscriptions file, with
// their hierarchy levels joined by Sora's delimiter. The names are still in the
// encoding of the maildir's folder names (modified UTF-7 for Dovecot).
func parseDovecotSubscriptions(content string) []string {
	delim := string(consts.MailboxDelimiter)
	version2 := strings.HasPrefix(content, dovecotSubscriptionsV2Header)
	// An unversioned Dovecot file separates levels with '.' (Maildir++), which the
	// folder import, resolveMailboxName, turns into '/' in the directory names too.
	unversioned := false
	switch {
	case version2:
		content = content[len(dovecotSubscriptionsV2Header):]
	case strings.HasPrefix(content, soraSubscriptionsHeader):
		content = content[len(soraSubscriptionsHeader):]
	default:
		unversioned = true
	}

	var names []string
	for _, line := range strings.Split(content, "\n") {
		// Dovecot reads lines with i_stream_next_line, which drops the CR of a CRLF.
		line = strings.TrimSuffix(line, "\r")
		switch {
		case version2:
			levels := strings.Split(line, "\t")
			for i, level := range levels {
				levels[i] = dovecotTabUnescape(level)
			}
			line = strings.Join(levels, delim)
		case unversioned:
			line = strings.ReplaceAll(line, ".", delim)
		}
		// Dovecot drops a trailing separator, which old versions and other software
		// wrote (mailbox_list_subscription_fill_one).
		line = strings.TrimSuffix(line, delim)
		if line == "" {
			continue
		}
		names = append(names, line)
	}
	return names
}

// formatDovecotSubscriptions returns a version 2 subscriptions file naming names,
// whose hierarchy levels are separated by Sora's delimiter.
func formatDovecotSubscriptions(names []string) string {
	var b strings.Builder
	b.WriteString(dovecotSubscriptionsV2Header)
	for _, name := range names {
		for i, level := range strings.Split(name, string(consts.MailboxDelimiter)) {
			if i > 0 {
				b.WriteByte('\t')
			}
			b.WriteString(dovecotTabEscaper.Replace(level))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// dovecotTabEscaper is Dovecot's str_append_tabescaped: \001, TAB, CR and LF are
// written as \001 followed by '1', 't', 'r' and 'n'.
var dovecotTabEscaper = strings.NewReplacer("\x01", "\x011", "\t", "\x01t", "\r", "\x01r", "\n", "\x01n")

// dovecotTabUnescape is Dovecot's str_append_tabunescaped: \001 followed by '0', '1',
// 't', 'r' or 'n' stands for NUL, \001, TAB, CR or LF, followed by any other byte for
// that byte; a \001 at the very end is dropped.
func dovecotTabUnescape(s string) string {
	if !strings.Contains(s, "\x01") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\x01' {
			b.WriteByte(s[i])
			continue
		}
		if i++; i == len(s) {
			break
		}
		switch s[i] {
		case '0':
			b.WriteByte(0)
		case '1':
			b.WriteByte('\x01')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'n':
			b.WriteByte('\n')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
