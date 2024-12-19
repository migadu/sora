package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	_ "github.com/emersion/go-message/charset"
	"github.com/migadu/sora/server"
)

type IMAPSession struct {
	server.Session
	server  *IMAPServer
	conn    *imapserver.Conn
	user    *server.SoraUser
	mailbox *SoraMailbox
}

func (s *IMAPSession) internalError(format string, a ...interface{}) *imap.Error {
	s.Log(format, a...)
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeServerBug,
		Text: fmt.Sprintf(format, a...),
	}
}
