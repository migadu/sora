package imap

import (
	"context"
	"unicode"
	"unicode/utf8"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Namespace(ctx context.Context) (*imap.NamespaceData, error) {
	if err := s.requireCapability(imap.CapNamespace, "NAMESPACE"); err != nil {
		return nil, err
	}
	data := &imap.NamespaceData{
		Personal: []imap.NamespaceDescriptor{
			{
				Prefix: "",
				Delim:  consts.MailboxDelimiter,
			},
		},
		Other: nil,
	}

	// Add shared namespace if feature is enabled
	if s.server.config != nil && s.server.config.SharedMailboxes.Enabled {
		data.Shared = []imap.NamespaceDescriptor{
			{
				Prefix: s.server.config.SharedMailboxes.NamespacePrefix,
				Delim:  consts.MailboxDelimiter,
			},
		}
	}

	return data, nil
}

// inSharedNamespace reports whether the mailbox named name is in the shared namespace
// NAMESPACE advertises: the root sharedRoot ("Shared" for the prefix "Shared/"), a
// \Noselect container, or a mailbox below it, in any case. sharedRoot is
// sharedNamespaceRoot(), "" while sharing is disabled. It classifies names as
// config.SharedMailboxesConfig.InNamespace does when a mailbox is created, without
// allocating: NOTIFY asks it for every mailbox on every tick.
//
// Everything else is in the personal namespace, the prefix "". ESEARCH IN (PERSONAL)
// and NOTIFY's PERSONAL both take "all selectable mailboxes in the user's personal
// namespace(s)" (RFC 5465 §6.2, RFC 7377 §2.2), so both ask this, never who owns the
// mailbox: a shared mailbox the user created is the user's own.
func inSharedNamespace(name, sharedRoot string) bool {
	if sharedRoot == "" {
		return false
	}
	// Match strings.ToLower in the creation policy, not Unicode case folding:
	// final sigma and long s must remain distinct, and lowercasing can change
	// UTF-8 widths (for example, İ becomes i). Walk both names independently.
	for sharedRoot != "" {
		if name == "" {
			return false
		}
		n, nameSize := utf8.DecodeRuneInString(name)
		r, rootSize := utf8.DecodeRuneInString(sharedRoot)
		if unicode.ToLower(n) != unicode.ToLower(r) {
			return false
		}
		name, sharedRoot = name[nameSize:], sharedRoot[rootSize:]
	}
	return name == "" || name[0] == byte(consts.MailboxDelimiter)
}

// sharedRootDestinationRefusal refuses the shared namespace root as the mailbox that
// APPEND, COPY or MOVE stores messages in. The root is a container: LIST marks it
// \Noselect, "It is not possible to use this name as a selectable mailbox" (RFC 9051
// §7.3.1), and SELECT refuses it, so a message stored there could not be read. CREATE
// refuses the root too, so the answer is [CANNOT] whether or not it exists, never
// [TRYCREATE] (RFC 9051 §6.3.12, §6.4.7). It returns nil for any other name.
func (s *IMAPSession) sharedRootDestinationRefusal(command, name string) *imap.Error {
	if s.server.config == nil || !s.server.config.SharedMailboxes.IsNamespaceRoot(name) {
		return nil
	}
	s.DebugLog("refusing the shared namespace root as a destination", "command", command, "mailbox", name)
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeCannot,
		Text: "The shared namespace root holds no messages. Use a mailbox under it instead",
	}
}
