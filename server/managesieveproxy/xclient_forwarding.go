package managesieveproxy

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/migadu/sora/server"
)

// sendForwardingParametersToBackend sends an XCLIENT-style command to the backend server
// with forwarding parameters containing the real client information.
// NOTE: This function was added for review completeness, based on pop3proxy.
func (s *Session) sendForwardingParametersToBackend(writer *bufio.Writer, reader *bufio.Reader) error {
	// The session does not have proxyInfo, so we pass nil.
	// NewForwardingParams will extract IPs from the connection itself.
	forwardingParams := server.NewForwardingParams(s.clientConn, nil)

	// Add session-specific details not handled by NewForwardingParams
	forwardingParams.SessionID = s.generateSessionID()
	forwardingParams.Variables["proxy-server"] = s.server.hostname
	forwardingParams.Variables["proxy-user"] = s.username

	// Also forward the proxy's source IP address for this specific backend connection.
	// This helps the backend log both the client IP and the proxy IP, even if it
	// overwrites its session's remote address with the client's IP.
	proxySrcIP, _ := server.GetHostPortFromAddr(s.backendConn.LocalAddr())
	forwardingParams.Variables["proxy-source-ip"] = proxySrcIP

	// Convert to a generic key-value format for a custom XCLIENT-like command.
	// ManageSieve does not have a standard XCLIENT, so this assumes a custom implementation.
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
			log.Printf("[ManageSieve Proxy] Warning: failed to clear read deadline after XCLIENT response: %v", err)
		}
	}()

	// Read backend response (we expect an OK response)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read XCLIENT response: %v", err)
	}

	response = strings.TrimRight(response, "\r\n")

	if strings.HasPrefix(response, "OK") {
		log.Printf("[ManageSieve Proxy] XCLIENT forwarding completed successfully for %s: %s", s.username, xclientParams)
	} else if strings.HasPrefix(response, "NO") || strings.HasPrefix(response, "BAD") {
		return fmt.Errorf("backend rejected XCLIENT command: %s", response)
	} else {
		// Unexpected response - log but don't fail
		log.Printf("[ManageSieve Proxy] Unexpected XCLIENT response from backend: %s", response)
	}

	return nil
}

// generateSessionID creates a unique session identifier for this proxy session.
func (s *Session) generateSessionID() string {
	// Generate a unique session ID for tracking.
	// A combination of protocol, hostname, username, and a random number
	// provides a reasonably unique identifier for logging and debugging.
	return fmt.Sprintf("managesieve-proxy-%s-%s-%d", s.server.hostname, s.username, rand.Intn(1000000))
}
