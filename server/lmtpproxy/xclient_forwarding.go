package lmtpproxy

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/migadu/sora/server"
)

// sendForwardingParametersToBackend sends an XCLIENT command to the backend server
// with forwarding parameters containing the real client information
func (s *Session) sendForwardingParametersToBackend(writer *bufio.Writer, reader *bufio.Reader) error {
	// Create forwarding parameters using the helper function.
	// Pass proxyInfo if available from PROXY protocol header.
	// NewForwardingParams will extract real client IP from PROXY protocol or connection.
	forwardingParams := server.NewForwardingParams(s.clientConn, s.proxyInfo)

	// Add proxy-specific information. Reuse the session id generated at construction so
	// the proxy's logs (session=<id>) and the backend's logs (proxy_session=<id>) match.
	forwardingParams.SessionID = s.sessionID
	// Use ESMTP for PROTO parameter as per Postfix XCLIENT spec (valid values: SMTP, ESMTP)
	forwardingParams.Protocol = "ESMTP"

	// Forward the client's announced HELO/LHLO name so the backend's Received: trace can name
	// the real upstream rather than this proxy. NewForwardingParams only fills in the client
	// IP/port, never the HELO.
	if s.clientHelo != "" {
		forwardingParams.HELO = s.clientHelo
	}

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
			s.DebugLog("failed to clear read deadline after XCLIENT", "error", err)
		}
	}()

	// Read backend response (we expect "250 OK" or similar).
	// Bounded so a misbehaving backend cannot grow memory without limit.
	response, err := server.ReadBoundedLine(reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to read XCLIENT response: %v", err)
	}

	response = strings.TrimRight(response, "\r\n")

	if strings.HasPrefix(response, "250") {
		s.DebugLog("XCLIENT forwarding completed", "params", xclientParams)
	} else if strings.HasPrefix(response, "220") {
		// XCLIENT succeeded - server reset session and sent new greeting
		s.DebugLog("XCLIENT accepted - server reset session", "greeting", response)

		// After XCLIENT, the session resets and we need to send LHLO again
		lhloCommand := fmt.Sprintf("LHLO %s\r\n", s.server.hostname)
		if _, err := writer.WriteString(lhloCommand); err != nil {
			return fmt.Errorf("failed to write LHLO after XCLIENT: %v", err)
		}
		if err := writer.Flush(); err != nil {
			return fmt.Errorf("failed to flush LHLO after XCLIENT: %v", err)
		}

		// Read LHLO response lines until we get the final one (without "-").
		// Bounded line length and line count; the read deadline set above still applies.
		for lines := 0; ; lines++ {
			if lines >= maxLHLOResponseLines {
				return fmt.Errorf("backend LHLO response after XCLIENT exceeded %d lines", maxLHLOResponseLines)
			}
			lhloResponse, err := server.ReadBoundedLine(reader, 4096)
			if err != nil {
				return fmt.Errorf("failed to read LHLO response after XCLIENT: %v", err)
			}
			lhloResponse = strings.TrimRight(lhloResponse, "\r\n")
			s.DebugLog("backend LHLO after XCLIENT", "response", lhloResponse)

			// A line is a continuation only if it explicitly has '-' after the
			// status code; everything else (including short lines like "250",
			// which previously caused an index-out-of-range panic here) is final.
			if len(lhloResponse) < 4 || lhloResponse[3] != '-' {
				break
			}
		}

		s.DebugLog("XCLIENT and session reset completed")
	} else if strings.HasPrefix(response, "550") || strings.HasPrefix(response, "5") {
		return fmt.Errorf("backend rejected XCLIENT command: %s", response)
	} else {
		// Unexpected response - log but don't fail
		s.DebugLog("unexpected XCLIENT response", "response", response)
	}

	return nil
}
