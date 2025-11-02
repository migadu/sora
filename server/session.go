package server

import (
	"fmt"

	"github.com/migadu/sora/logger"
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

func (s *Session) Log(format string, args ...any) {
	user := "none"
	if s.User != nil {
		user = fmt.Sprintf("%s/%d", s.FullAddress(), s.AccountID())
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
			logger.Info("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "conn_total", s.Stats.GetTotalConnections(), "msg", fmt.Sprintf(format, args...))
		} else {
			logger.Info("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "conn_total", s.Stats.GetTotalConnections(), "conn_auth", s.Stats.GetAuthenticatedConnections(), "msg", fmt.Sprintf(format, args...))
		}
	} else {
		logger.Info("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "msg", fmt.Sprintf(format, args...))
	}
}

func (s *Session) DebugLog(format string, args ...any) {
	user := "none"
	if s.User != nil {
		user = fmt.Sprintf("%s/%d", s.FullAddress(), s.AccountID())
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
			logger.Debug("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "conn_total", s.Stats.GetTotalConnections(), "msg", fmt.Sprintf(format, args...))
		} else {
			logger.Debug("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "conn_total", s.Stats.GetTotalConnections(), "conn_auth", s.Stats.GetAuthenticatedConnections(), "msg", fmt.Sprintf(format, args...))
		}
	} else {
		logger.Debug("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "msg", fmt.Sprintf(format, args...))
	}
}

func (s *Session) WarnLog(format string, args ...any) {
	user := "none"
	if s.User != nil {
		user = fmt.Sprintf("%s/%d", s.FullAddress(), s.AccountID())
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
			logger.Warn("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "conn_total", s.Stats.GetTotalConnections(), "msg", fmt.Sprintf(format, args...))
		} else {
			logger.Warn("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "conn_total", s.Stats.GetTotalConnections(), "conn_auth", s.Stats.GetAuthenticatedConnections(), "msg", fmt.Sprintf(format, args...))
		}
	} else {
		logger.Warn("Session", "protocol", protocolPrefix, "conn", connInfo, "user", user, "session", s.Id, "msg", fmt.Sprintf(format, args...))
	}
}
