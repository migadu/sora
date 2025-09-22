package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Namespace() (*imap.NamespaceData, error) {
	return &imap.NamespaceData{
		Personal: []imap.NamespaceDescriptor{
			{
				Prefix: "",
				Delim:  consts.MailboxDelimiter,
			},
		},
		Other:  nil,
		Shared: nil,
	}, nil
}
