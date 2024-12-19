package imap

func (s *IMAPSession) Capabilities() []string {
	var caps []string
	for cap := range s.server.caps {
		caps = append(caps, string(cap))
	}
	return caps
}
