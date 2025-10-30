package lmtpproxy

import (
	"bufio"
	"fmt"
	"github.com/migadu/sora/logger"
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
	// Use ESMTP for PROTO parameter as per Postfix XCLIENT spec (valid values: SMTP, ESMTP)
	forwardingParams.Protocol = "ESMTP"

	// Don't set ProxyTTL for LMTP XCLIENT since it's not commonly supported
	// and causes "501 Bad command" errors with standard LMTP servers
	forwardingParams.ProxyTTL = 0
	forwardingParams.Variables["proxy-server"] = s.server.hostname
	if s.username != "" {
		forwardingParams.Variables["proxy-user"] = s.username
	}

	// Also forward the proxy's source IP address for this specific backend connection.
	// This helps the backend log both the client IP and the proxy IP, even if it
	// overwrites its session's remote address with the client's IP.
	proxySrcIP, _ := server.GetHostPortFromAddr(s.backendConn.LocalAddr())
	forwardingParams.Variables["proxy-source-ip"] = proxySrcIP

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
			logger.Debug("LMTP Proxy: Warning - failed to clear read deadline after XCLIENT", "name", s.server.name, "error", err)
		}
	}()

	// Read backend response (we expect "250 OK" or similar)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read XCLIENT response: %v", err)
	}

	response = strings.TrimRight(response, "\r\n")

	if strings.HasPrefix(response, "250") {
		logger.Debug("LMTP Proxy: XCLIENT forwarding completed", "name", s.server.name, "user", s.username, "params", xclientParams)
	} else if strings.HasPrefix(response, "220") {
		// XCLIENT succeeded - server reset session and sent new greeting
		logger.Debug("LMTP Proxy: XCLIENT accepted - server reset session", "name", s.server.name, "greeting", response)

		// After XCLIENT, the session resets and we need to send LHLO again
		lhloCommand := fmt.Sprintf("LHLO %s\r\n", s.server.hostname)
		if _, err := writer.WriteString(lhloCommand); err != nil {
			return fmt.Errorf("failed to write LHLO after XCLIENT: %v", err)
		}
		if err := writer.Flush(); err != nil {
			return fmt.Errorf("failed to flush LHLO after XCLIENT: %v", err)
		}

		// Read LHLO response lines until we get the final one (without "-")
		for {
			lhloResponse, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read LHLO response after XCLIENT: %v", err)
			}
			lhloResponse = strings.TrimRight(lhloResponse, "\r\n")
			logger.Debug("LMTP Proxy: Backend LHLO after XCLIENT", "name", s.server.name, "response", lhloResponse)

			// Check if this is the final response line (doesn't have "-" after status code)
			if len(lhloResponse) >= 3 && lhloResponse[3] != '-' {
				break
			}
		}

		logger.Debug("LMTP Proxy: XCLIENT and session reset completed", "name", s.server.name, "user", s.username)
	} else if strings.HasPrefix(response, "550") || strings.HasPrefix(response, "5") {
		return fmt.Errorf("backend rejected XCLIENT command: %s", response)
	} else {
		// Unexpected response - log but don't fail
		logger.Debug("LMTP Proxy: Unexpected XCLIENT response", "name", s.server.name, "response", response)
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
