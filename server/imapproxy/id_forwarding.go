package imapproxy

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/migadu/sora/server"
)

// generateSessionID creates a unique session identifier for this proxy session
func (s *Session) generateSessionID() string {
	// Generate a unique session ID for tracking.
	// A combination of protocol, hostname, username, and a random number
	// provides a reasonably unique identifier for logging and debugging.
	return fmt.Sprintf("imap-proxy-%s-%s-%d", s.server.hostname, s.username, rand.Intn(1000000))
}

// sendForwardingParametersToBackend sends an ID command to the backend server
// with forwarding parameters containing the real client information
func (s *Session) sendForwardingParametersToBackend() error {
	// Create forwarding parameters using the helper function.
	// The session does not have proxyInfo, so we pass nil.
	forwardingParams := server.NewForwardingParams(s.clientConn, nil)

	// Add proxy-specific information
	forwardingParams.SessionID = s.generateSessionID()
	forwardingParams.Variables["proxy-server"] = s.server.hostname
	forwardingParams.Variables["proxy-user"] = s.username

	// Also forward the proxy's source IP address for this specific backend connection.
	// This helps the backend log both the client IP and the proxy IP, even if it
	// overwrites its session's remote address with the client's IP.
	proxySrcIP, _ := server.GetHostPortFromAddr(s.backendConn.LocalAddr())
	forwardingParams.Variables["proxy-source-ip"] = proxySrcIP

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

	// Generate a random tag to avoid conflicts with client tags
	tag := fmt.Sprintf("p%d", rand.Intn(10000))
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
			log.Printf("IMAP Proxy [%s] Warning: failed to clear read deadline after ID response: %v", s.server.name, err)
		}
	}()

	// Read backend response (we expect "* ID (...)" followed by "A002 OK")
	for {
		response, err := s.backendReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read ID response: %v", err)
		}

		response = strings.TrimRight(response, "\r\n")

		// Log the backend's ID response for debugging
		if strings.HasPrefix(response, "* ID") {
			log.Printf("IMAP Proxy [%s] Backend ID response: %s", s.server.name, response)
		} else if strings.HasPrefix(response, tag+" OK") {
			log.Printf("IMAP Proxy [%s] ID forwarding completed successfully for %s", s.server.name, s.username)
			break
		} else if strings.HasPrefix(response, tag+" NO") || strings.HasPrefix(response, tag+" BAD") {
			return fmt.Errorf("backend rejected ID command: %s", response)
		}
	}

	return nil
}

// escapeIMAPString escapes characters that have special meaning in IMAP strings.
func escapeIMAPString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
