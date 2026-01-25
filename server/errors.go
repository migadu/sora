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

// Authentication error sentinels
var (
	// ErrServerShuttingDown indicates that authentication failed because the server is shutting down
	ErrServerShuttingDown = errors.New("server is shutting down, please try again")

	// ErrAuthServiceUnavailable indicates that an authentication service (e.g., remotelookup) is temporarily unavailable
	ErrAuthServiceUnavailable = errors.New("authentication service temporarily unavailable, please try again later")

	// ErrUserNotFound indicates that the user was not found (permanent failure - 550)
	ErrUserNotFound = errors.New("user not found")

	// ErrUserNotFoundTempFail indicates user not found but with temp failure response (450)
	ErrUserNotFoundTempFail = errors.New("user not found (temporary failure)")
)

// Backend connection/authentication error sentinels (for proxy servers)
var (
	// ErrBackendConnectionFailed indicates the proxy could not connect to the backend server
	ErrBackendConnectionFailed = errors.New("failed to connect to backend server")

	// ErrBackendAuthFailed indicates the proxy could not authenticate to the backend server
	ErrBackendAuthFailed = errors.New("failed to authenticate to backend server")

	// ErrBackendTimeout indicates a timeout occurred while communicating with the backend
	ErrBackendTimeout = errors.New("backend server timeout")

	// ErrBackendUnavailable is a general error for any backend unavailability
	ErrBackendUnavailable = errors.New("backend server temporarily unavailable")
)

// IsTemporaryAuthFailure checks if an authentication error is temporary (server shutdown, service unavailable)
// and should result in an UNAVAILABLE response rather than AUTHENTICATIONFAILED.
func IsTemporaryAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrServerShuttingDown) || errors.Is(err, ErrAuthServiceUnavailable)
}

// IsBackendError checks if an error is related to backend connectivity or authentication.
// These errors should result in "Backend server temporarily unavailable" responses
// rather than "Authentication failed" (which implies wrong credentials).
func IsBackendError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrBackendConnectionFailed) ||
		errors.Is(err, ErrBackendAuthFailed) ||
		errors.Is(err, ErrBackendTimeout) ||
		errors.Is(err, ErrBackendUnavailable)
}

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
		// Check if the connection was closed (net.ErrClosed wraps poll.ErrNetClosing)
		if errors.Is(opErr.Err, net.ErrClosed) {
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

	// Handle TLS alert errors (e.g., handshake failures, bad certificates, unsupported versions)
	// AlertError represents TLS alerts which are typically client-side issues
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return true
	}

	// Handle certificate verification errors
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}

	// Handle general TLS errors as fallback
	// Note: Some TLS errors may not be wrapped in AlertError, so we check for "tls:" prefix
	errMsg := err.Error()
	if strings.Contains(errMsg, "tls:") || strings.Contains(errMsg, "remote error: tls:") {
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
