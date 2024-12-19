package imap

func (s *IMAPSession) Close() error {
	if s.user != nil {
		s.Log("Closing session for user: %v", s.user.Address())
		s.user = nil
	}
	s.mailbox = nil
	return nil
}
