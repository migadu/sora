package lmtpproxy

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/migadu/sora/server"
)

// sendForwardingParametersToBackend sends an XCLIENT command to the backend server
// with forwarding parameters containing the real client information
func (s *Session) sendForwardingParametersToBackend(writer *bufio.Writer, reader *bufio.Reader) error {
	// Create forwarding parameters using the helper function.
	// The session does not have proxyInfo, so we pass nil.
	forwardingParams := server.NewForwardingParams(s.clientConn, nil)

	// Add proxy-specific information
	forwardingParams.SessionID = s.generateSessionID()
	forwardingParams.Protocol = "LMTP"
	forwardingParams.Variables["proxy-server"] = s.server.hostname
	if s.username != "" {
		forwardingParams.Variables["proxy-user"] = s.username
	}

	// Convert to LMTP XCLIENT format
	xclientParams := forwardingParams.ToLMTPXCLIENT()

	// Send XCLIENT command to backend
	xclientCommand := fmt.Sprintf("XCLIENT %s\r\n", xclientParams)

	if _, err := writer.WriteString(xclientCommand); err != nil {
		return fmt.Errorf("failed to write XCLIENT command: %v", err)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush XCLIENT command: %v", err)
	}

	// Set a deadline for reading the response to prevent hanging.
	readTimeout := s.server.connManager.GetConnectTimeout()
	if err := s.backendConn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline for XCLIENT response: %w", err)
	}
	// Ensure the deadline is cleared when the function returns.
	defer func() {
		if err := s.backendConn.SetReadDeadline(time.Time{}); err != nil {
			log.Printf("[LMTP Proxy] Warning: failed to clear read deadline after XCLIENT response: %v", err)
		}
	}()

	// Read backend response (we expect "250 OK" or similar)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read XCLIENT response: %v", err)
	}

	response = strings.TrimRight(response, "\r\n")

	if strings.HasPrefix(response, "250") {
		log.Printf("[LMTP Proxy] XCLIENT forwarding completed successfully for %s: %s", s.username, xclientParams)
	} else if strings.HasPrefix(response, "550") || strings.HasPrefix(response, "5") {
		return fmt.Errorf("backend rejected XCLIENT command: %s", response)
	} else {
		// Unexpected response - log but don't fail
		log.Printf("[LMTP Proxy] Unexpected XCLIENT response from backend: %s", response)
	}

	return nil
}

// generateSessionID creates a unique session identifier for this proxy session
func (s *Session) generateSessionID() string {
	// Generate a unique session ID for tracking.
	sessionUser := s.username
	if sessionUser == "" {
		sessionUser = "unknown"
	}
	// A combination of protocol, hostname, username, and a random number
	// provides a reasonably unique identifier for logging and debugging.
	return fmt.Sprintf("lmtp-proxy-%s-%s-%d", s.server.hostname, sessionUser, rand.Intn(1000000))
}
