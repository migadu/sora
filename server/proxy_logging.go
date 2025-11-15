package server

import (
	"net"

	"github.com/migadu/sora/logger"
)

// ProxySessionLogger provides common logging functionality for proxy sessions.
type ProxySessionLogger struct {
	Protocol   string
	ServerName string
	ClientConn net.Conn
	Username   string
	AccountID  int64
	Debug      bool
}

// log is the common logging implementation for all log levels
func (l *ProxySessionLogger) log(logFn logFunc, msg string, keysAndValues ...any) {
	remoteAddr := GetAddrString(l.ClientConn.RemoteAddr())

	allKeyvals := []any{"proto", l.Protocol, "name", l.ServerName, "remote", remoteAddr}

	// Add user email if available
	if l.Username != "" {
		allKeyvals = append(allKeyvals, "user", l.Username)
	}

	// Add account_id if available
	if l.AccountID > 0 {
		allKeyvals = append(allKeyvals, "account_id", l.AccountID)
	}

	allKeyvals = append(allKeyvals, keysAndValues...)
	logFn(msg, allKeyvals...)
}

// InfoLog logs at INFO level with session context
func (l *ProxySessionLogger) InfoLog(msg string, keysAndValues ...any) {
	l.log(logger.Info, msg, keysAndValues...)
}

// DebugLog logs at DEBUG level with session context
func (l *ProxySessionLogger) DebugLog(msg string, keysAndValues ...any) {
	if l.Debug {
		l.log(logger.Debug, msg, keysAndValues...)
	}
}

// WarnLog logs at WARN level with session context
func (l *ProxySessionLogger) WarnLog(msg string, keysAndValues ...any) {
	l.log(logger.Warn, msg, keysAndValues...)
}
