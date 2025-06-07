package imap

import (
	"github.com/emersion/go-imap/v2"
)

// ID handles the IMAP ID command (RFC 2971)
// It logs the client-provided ID information and returns server ID information
func (s *IMAPSession) ID(clientID *imap.IDData) *imap.IDData {
	if clientID != nil {
		s.Log("[ID] Client identified itself with: Name=%s Version=%s OS=%s OSVersion=%s Vendor=%s",
			clientID.Name, clientID.Version, clientID.OS, clientID.OSVersion, clientID.Vendor)
	} else {
		s.Log("[ID] Client sent empty ID command")
	}

	return &imap.IDData{
		Name:       "Sora",
		Version:    "1.0.0", // TODO Get right version
		Vendor:     "Migadu",
		SupportURL: "https://migadu.com",
	}
}
