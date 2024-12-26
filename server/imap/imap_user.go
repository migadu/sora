package imap

import (
	"sync"

	"github.com/migadu/sora/server"
)

type IMAPUser struct {
	server.User
	mutex sync.Mutex
	// prevUidValidity uint32
}

func NewIMAPUser(address server.Address, userID int) *IMAPUser {
	return &IMAPUser{
		User: *server.NewUser(address, userID),
	}
}

func (u *IMAPUser) UserID() int {
	return u.User.UserID()
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
