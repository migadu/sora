package imap

import (
	"context"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Namespace(ctx context.Context) (*imap.NamespaceData, error) {
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
