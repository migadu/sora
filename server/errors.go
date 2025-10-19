package server

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// IsConnectionError checks if an error is a common, non-fatal network connection error.
// These errors are typically logged and the connection is closed, but they should not crash the server.
// This helps distinguish between client-side issues (e.g., connection reset) and genuine server problems.
func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common network error types
	var netErr net.Error
	var opErr *net.OpError
	var syscallErr *os.SyscallError
	var tlsRecordHeaderError tls.RecordHeaderError

	// Handle direct network errors (e.g., timeouts)
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Handle network operation errors, which wrap other network-related errors
	if errors.As(err, &opErr) {
		// "read: connection reset by peer" is a common client-side disconnection
		if errors.Is(opErr.Err, syscall.ECONNRESET) {
			return true
		}
		// "use of closed network connection" can happen if the connection is closed by another goroutine
		if strings.Contains(opErr.Err.Error(), "use of closed network connection") {
			return true
		}
	}

	// Handle syscall errors, which can indicate low-level network issues
	if errors.As(err, &syscallErr) {
		if errors.Is(syscallErr.Err, syscall.ECONNRESET) || errors.Is(syscallErr.Err, syscall.EPIPE) {
			return true
		}
	}

	// Handle TLS handshake errors
	if errors.As(err, &tlsRecordHeaderError) {
		return true
	}

	// Handle EOF, which can occur if the client disconnects abruptly
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	// Handle PROXY protocol specific non-fatal errors
	if errors.Is(err, ErrNoProxyHeader) {
		return true
	}

	return false
}
