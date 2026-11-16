package imapproxy

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/migadu/sora/server"
)

// errIDRefused is the backend refusing the forwarded ID with a tagged NO or BAD. Its
// tagged reply was read, so the stream is at a command boundary and the login can go on
// without the forwarding parameters. Any other error of the exchange leaves the reply
// unread, or partly read, and the connection unusable.
var errIDRefused = errors.New("backend rejected ID command")

// sendForwardingParametersToBackend sends an ID command to the backend server
// with forwarding parameters containing the real client information
func (s *Session) sendForwardingParametersToBackend() error {
	// Create forwarding parameters using the helper function. With a PROXY header the
	// client is its source address, not the socket peer (the load balancer).
	forwardingParams := server.NewForwardingParams(s.clientConn, s.proxyInfo)

	// Add proxy-specific information. The session id is generated once at session
	// construction and reused here so the proxy's logs (session=<id>) and the
	// backend's logs (proxy_session=<id>) share the same value for tracing.
	forwardingParams.SessionID = s.sessionID
	forwardingParams.Variables["proxy-server"] = s.server.hostname
	forwardingParams.Variables["proxy-user"] = s.username

	// Also forward the proxy's source IP address for this specific backend connection.
	// This helps the backend log both the client IP and the proxy IP, even if it
	// overwrites its session's remote address with the client's IP.
	proxySrcIP, _ := server.GetHostPortFromAddr(s.backendConn.LocalAddr())
	forwardingParams.Variables["proxy-source-ip"] = proxySrcIP

	// Forward JA4 TLS fingerprint if available
	// The fingerprint is crucial for capability filtering on the backend
	if ja4Conn, ok := s.listenerConn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
		fingerprint, err := ja4Conn.GetJA4Fingerprint()
		if err == nil && fingerprint != "" {
			forwardingParams.Variables["ja4-fingerprint"] = fingerprint
			s.DebugLog("forwarding JA4 fingerprint", "fingerprint", fingerprint)
		}
	}

	// Convert to IMAP ID format
	forwardingFields := forwardingParams.ToIMAPID()

	// Add a standard field to the forwarded ID. Some IMAP server libraries (like go-imap/v2)
	// may default to sending "* ID NIL" if the client's ID command contains only
	// non-standard (e.g., x-*) keys. Including a "name" field ensures the backend responds correctly.
	forwardingFields["name"] = "Sora-Proxy"

	// Build ID command
	var fields []string
	for key, value := range forwardingFields {
		// IMAP literals need to be properly quoted
		fields = append(fields, fmt.Sprintf(`"%s" "%s"`, escapeIMAPString(key), escapeIMAPString(value)))
	}

	// Generate a random tag to avoid conflicts with client tags. Its prefix differs from
	// the AUTHENTICATE tag's, so the two replies can never be taken for each other.
	tag := fmt.Sprintf("i%d", rand.Intn(10000))
	idCommand := fmt.Sprintf("%s ID (%s)\r\n", tag, strings.Join(fields, " "))

	// Send ID command to backend
	if _, err := s.backendWriter.WriteString(idCommand); err != nil {
		return fmt.Errorf("failed to write ID command: %v", err)
	}

	if err := s.backendWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush ID command: %v", err)
	}

	// Set a deadline for reading the response to prevent hanging.
	// This mirrors the robust implementation in the authenticateToBackend function.
	readTimeout := s.server.connManager.GetConnectTimeout()
	if err := s.backendConn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline for ID response: %w", err)
	}
	// Ensure the deadline is cleared when the function returns.
	defer func() {
		if err := s.backendConn.SetReadDeadline(time.Time{}); err != nil {
			s.WarnLog("failed to clear read deadline after ID response", "error", err)
		}
	}()

	// Read backend response (we expect "* ID (...)" followed by the tagged OK). The tagged
	// reply ends the exchange whatever its status (RFC 9051 section 2.2.2). The read is
	// bounded like every other backend read: RFC 2971 section 3.3 keeps a
	// well-formed ID response far below 64 KiB (at most 30 pairs of a field of up to 30
	// octets and a value of up to 1024).
	warnedTooLong := false
	for {
		response, err := server.ReadBoundedLine(s.backendReader, 65536)
		if errors.Is(err, server.ErrLineTooLong) {
			// ReadBoundedLine drained the line. Read on to the tagged reply: only it
			// tells a refusal, after which the login goes on, from an exchange left
			// unfinished, which fails the backend leg.
			if !warnedTooLong {
				s.WarnLog("skipping oversized line in backend ID response", "backend", s.serverAddr)
				warnedTooLong = true
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to read ID response: %w", err)
		}

		response = strings.TrimRight(response, "\r\n")

		responseTag, ok := statusOK(response)
		if responseTag != tag {
			// The backend's own "* ID (...)", or other data before the tagged reply
			s.DebugLog("backend ID response", "response", response)
			continue
		}
		if !ok {
			return fmt.Errorf("%w: %s", errIDRefused, response)
		}
		s.DebugLog("ID forwarding completed successfully")
		return nil
	}
}

// escapeIMAPString escapes characters that have special meaning in IMAP strings.
func escapeIMAPString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
