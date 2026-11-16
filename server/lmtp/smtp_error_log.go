package lmtp

import (
	"fmt"
	"net"
	"strings"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"
)

// smtpErrorLog is the go-smtp server's ErrorLog. go-smtp reports through it what it
// handles on its own: a failed STARTTLS (a handshake that fails, or plain text the
// client sent behind the command), a connection that ended on an error, and a
// recovered panic. Each report is a record of the configured logger, so it follows
// the configured format, level and output: a log.Logger on logger.Stderr() wrote a
// plain line into a JSON log file, and with output = "syslog" wrote to stderr only.
//
// A recovered panic is a server bug and an ERROR; the rest are WARN. go-smtp passes
// the connection's remote address as the first argument, which becomes the remote
// attribute.
type smtpErrorLog struct{ name string }

func (l smtpErrorLog) Printf(format string, v ...any) {
	l.log(strings.HasPrefix(format, "panic "), fmt.Sprintf(format, v...), v)
}

func (l smtpErrorLog) Println(v ...any) {
	l.log(false, fmt.Sprintln(v...), v)
}

func (l smtpErrorLog) log(panicked bool, msg string, v []any) {
	msg = "LMTP: " + strings.TrimSuffix(msg, "\n")
	attrs := []any{"name", l.name}
	if len(v) > 0 {
		if addr, ok := v[0].(net.Addr); ok {
			attrs = append(attrs, "remote", server.GetAddrString(addr))
		}
	}
	if panicked {
		logger.Error(msg, attrs...)
		return
	}
	logger.Warn(msg, attrs...)
}
