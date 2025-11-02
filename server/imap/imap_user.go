package imap

import (
	"github.com/migadu/sora/server"
)

type IMAPUser struct {
	server.User
}

func NewIMAPUser(address server.Address, AccountID int64) *IMAPUser {
	return &IMAPUser{
		User: *server.NewUser(address, AccountID),
	}
}

func (u *IMAPUser) AccountID() int64 {
	return u.User.AccountID()
}

func (u *IMAPUser) Domain() string {
	return u.User.Domain()
}

func (u *IMAPUser) LocalPart() string {
	return u.User.LocalPart()
}

func (u *IMAPUser) FullAddress() string {
	return u.User.FullAddress()
}
