package server

import (
	"fmt"
	"log"
	"time"
)

type Session struct {
	Id       string
	RemoteIP string
	*User
	HostName string
	Protocol string
}

func (s *Session) Log(format string, args ...interface{}) {
	now := time.Now().Format("2006-01-02 15:04:05")
	user := "unknown"
	if s.User != nil {
		user = fmt.Sprintf("%s/%d", s.FullAddress(), s.UserID())
	}
	log.Printf("%s %s remote=%s user=%s session=%s %s: %s",
		now,
		s.HostName,
		s.RemoteIP,
		user,
		s.Id,
		s.Protocol,
		fmt.Sprintf(format, args...),
	)
}
