package server

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/migadu/sora/tlsmanager"
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

	// Handle TLS errors from tlsmanager (client-side issues and transient server issues)
	if errors.Is(err, tlsmanager.ErrMissingServerName) ||
		errors.Is(err, tlsmanager.ErrHostNotAllowed) ||
		errors.Is(err, tlsmanager.ErrCertificateUnavailable) {
		return true
	}

	// Handle general TLS handshake errors from crypto/tls package
	// These include: unsupported versions, bad certificates, protocol errors, etc.
	// All TLS handshake failures are client-side issues and should not crash the server
	// Note: We use string matching because crypto/tls doesn't export typed errors for these cases
	errMsg := err.Error()
	if strings.Contains(errMsg, "unsupported versions") ||
		strings.Contains(errMsg, "tls: handshake failure") ||
		strings.Contains(errMsg, "tls: bad certificate") ||
		strings.Contains(errMsg, "tls: certificate required") ||
		strings.Contains(errMsg, "tls: unknown certificate") ||
		strings.Contains(errMsg, "tls: client offered only") ||
		strings.Contains(errMsg, "tls: no cipher suite") ||
		strings.Contains(errMsg, "tls: oversized record") ||
		strings.Contains(errMsg, "tls: first record does not look like a TLS handshake") ||
		strings.Contains(errMsg, "remote error: tls:") {
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
