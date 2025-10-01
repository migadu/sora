package server

import (
	"fmt"
	"log"
)

// ConnectionStatsProvider defines an interface for getting connection statistics
type ConnectionStatsProvider interface {
	GetTotalConnections() int64
	GetAuthenticatedConnections() int64
}

type Session struct {
	Id       string
	RemoteIP string // Real client IP (from PROXY protocol or direct connection)
	ProxyIP  string // Proxy IP (only set when connection comes through PROXY protocol)
	*User
	HostName   string
	ServerName string // Name of the server instance (e.g., "imap0", "pop3-backend")
	Protocol   string
	Stats      ConnectionStatsProvider

	// Parameter forwarding support (Dovecot-style)
	ForwardingParams *ForwardingParams // Forwarded connection parameters
}

func (s *Session) Log(format string, args ...interface{}) {
	user := "none"
	if s.User != nil {
		user = fmt.Sprintf("%s/%d", s.FullAddress(), s.UserID())
	}

	// Build connection info - show proxy= when proxied, remote= when direct
	var connInfo string
	if s.ProxyIP != "" {
		connInfo = fmt.Sprintf("remote=%s proxy=%s", s.RemoteIP, s.ProxyIP)
	} else {
		connInfo = fmt.Sprintf("remote=%s", s.RemoteIP)
	}

	// Build protocol prefix with server name if available
	var protocolPrefix string
	if s.ServerName != "" {
		protocolPrefix = fmt.Sprintf("%s-%s", s.Protocol, s.ServerName)
	} else {
		protocolPrefix = s.Protocol
	}

	if s.Stats != nil {
		if s.Protocol == "LMTP" {
			// LMTP has no authenticated sessions
			log.Printf("[%s] %s user=%s session=%s conn_total=%d: %s",
				protocolPrefix,
				connInfo,
				user,
				s.Id,
				s.Stats.GetTotalConnections(),
				fmt.Sprintf(format, args...),
			)
		} else {
			log.Printf("[%s] %s user=%s session=%s conn_total=%d conn_auth=%d: %s",
				protocolPrefix,
				connInfo,
				user,
				s.Id,
				s.Stats.GetTotalConnections(),
				s.Stats.GetAuthenticatedConnections(),
				fmt.Sprintf(format, args...),
			)
		}
	} else {
		log.Printf("[%s] %s user=%s session=%s: %s",
			protocolPrefix,
			connInfo,
			user,
			s.Id,
			fmt.Sprintf(format, args...),
		)
	}
}
