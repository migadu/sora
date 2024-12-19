package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
)

func (s *IMAPSession) Namespace() (*imap.NamespaceData, error) {
	return nil, fmt.Errorf("Namespace not implemented")
}
