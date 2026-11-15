package imap

import (
	"context"

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
