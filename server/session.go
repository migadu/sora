package server

import (
	"fmt"
	"log"
)

type Session struct {
	Id       string
	RemoteIP string
	*User
	HostName string
	Protocol string
}

func (s *Session) Log(format string, args ...interface{}) {
	user := "none"
	if s.User != nil {
		user = fmt.Sprintf("%s/%d", s.FullAddress(), s.UserID())
	}
	log.Printf("remote=%s user=%s session=%s %s: %s",
		s.RemoteIP,
		user,
		s.Id,
		s.Protocol,
		fmt.Sprintf(format, args...),
	)
}
