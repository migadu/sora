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

// logFunc is the type for logger functions (Info, Debug, Warn, Error)
type logFunc func(msg string, keyvals ...any)

// log is the common logging implementation for all log levels with structured key-value pairs
func (s *Session) log(logFn logFunc, msg string, keysAndValues ...any) {
	// Build protocol prefix with server name if available
	var protocolPrefix string
	if s.ServerName != "" {
		protocolPrefix = fmt.Sprintf("%s-%s", s.Protocol, s.ServerName)
	} else {
		protocolPrefix = s.Protocol
	}

	// Build base keyvals
	baseKeyvals := []any{"protocol", protocolPrefix, "remote", s.RemoteIP}

	// Add proxy IP if connection came through PROXY protocol
	if s.ProxyIP != "" {
		baseKeyvals = append(baseKeyvals, "proxy", s.ProxyIP)
	}

	// Always add user and account_id for consistent log structure (empty string/0 if not authenticated)
	if s.User != nil {
		baseKeyvals = append(baseKeyvals, "user", s.FullAddress(), "account_id", s.AccountID())
	} else {
		baseKeyvals = append(baseKeyvals, "user", "", "account_id", 0)
	}

	// Add session ID
	baseKeyvals = append(baseKeyvals, "session", s.Id)

	// Add stats if available
	if s.Stats != nil {
		if s.Protocol == "LMTP" {
			// LMTP has no authenticated sessions
			baseKeyvals = append(baseKeyvals, "conn_total", s.Stats.GetTotalConnections())
		} else {
			baseKeyvals = append(baseKeyvals, "conn_total", s.Stats.GetTotalConnections(), "conn_auth", s.Stats.GetAuthenticatedConnections())
		}
	}

	// Add the provided key-value pairs
	baseKeyvals = append(baseKeyvals, keysAndValues...)

	logFn(msg, baseKeyvals...)
}

// InfoLog logs at INFO level with session context and structured key-value pairs
func (s *Session) InfoLog(msg string, keysAndValues ...any) {
	s.log(logger.Info, msg, keysAndValues...)
}

// DebugLog logs at DEBUG level with session context and structured key-value pairs
func (s *Session) DebugLog(msg string, keysAndValues ...any) {
	s.log(logger.Debug, msg, keysAndValues...)
}

// WarnLog logs at WARN level with session context and structured key-value pairs
func (s *Session) WarnLog(msg string, keysAndValues ...any) {
	s.log(logger.Warn, msg, keysAndValues...)
}
