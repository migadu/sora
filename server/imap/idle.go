package imap

import (
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
)

var idlePollInterval = 15 * time.Second

func (s *IMAPSession) Idle(w *imapserver.UpdateWriter, done <-chan struct{}) error {
	s.Log("client entered IDLE mode")

	for {
		if stop, err := s.idleLoop(w, done); err != nil {
			return err
		} else if stop {
			return nil
		}
	}
}

func (s *IMAPSession) idleLoop(w *imapserver.UpdateWriter, done <-chan struct{}) (stop bool, err error) {
	timer := time.NewTimer(idlePollInterval)
	defer timer.Stop()

	select {
	case <-timer.C:
		return false, s.Poll(w, true)
	case <-done:
		return true, nil
	}
}
