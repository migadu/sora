package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Namespace() (*imap.NamespaceData, error) {
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
