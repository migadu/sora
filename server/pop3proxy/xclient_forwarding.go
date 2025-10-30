package pop3proxy

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
func (s *POP3ProxySession) sendForwardingParametersToBackend(writer *bufio.Writer, reader *bufio.Reader) error {
	// Create forwarding parameters using the helper function.
	// The session does not have proxyInfo, so we pass nil.
	// NewForwardingParams will extract IPs from the connection itself.
	forwardingParams := server.NewForwardingParams(s.clientConn, nil)

	// Add session-specific details not handled by NewForwardingParams
	forwardingParams.SessionID = s.generateSessionID()

	// Add proxy-specific information
	forwardingParams.Variables["proxy-server"] = s.server.hostname
	forwardingParams.Variables["proxy-user"] = s.username

	// Also forward the proxy's source IP address for this specific backend connection.
	// This helps the backend log both the client IP and the proxy IP, even if it
	// overwrites its session's remote address with the client's IP.
	proxySrcIP, _ := server.GetHostPortFromAddr(s.backendConn.LocalAddr())
	forwardingParams.Variables["proxy-source-ip"] = proxySrcIP

	// Convert to POP3 XCLIENT format
	xclientParams := forwardingParams.ToPOP3XCLIENT()

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
			logger.Debug("POP3 Proxy: Warning - failed to clear read deadline after XCLIENT response", "proxy", s.server.name, "error", err)
		}
	}()

	// Read backend response (we expect "+OK XCLIENT parameters accepted")
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read XCLIENT response: %v", err)
	}

	response = strings.TrimRight(response, "\r\n")

	if strings.HasPrefix(response, "+OK") {
		if s.server.debug {
			logger.Debug("POP3 Proxy: XCLIENT forwarding completed successfully", "proxy", s.server.name, "user", s.username, "params", xclientParams)
		}
	} else if strings.HasPrefix(response, "-ERR") {
		return fmt.Errorf("backend rejected XCLIENT command: %s", response)
	} else {
		// Unexpected response - log but don't fail
		logger.Debug("POP3 Proxy: Unexpected XCLIENT response from backend", "proxy", s.server.name, "response", response)
	}

	return nil
}

// generateSessionID creates a unique session identifier for this proxy session
func (s *POP3ProxySession) generateSessionID() string {
	// Generate a unique session ID for tracking.
	// A combination of protocol, hostname, username, and a random number
	// provides a reasonably unique identifier for logging and debugging.
	return fmt.Sprintf("pop3-proxy-%s-%s-%d", s.server.hostname, s.username, rand.Intn(1000000))
}
