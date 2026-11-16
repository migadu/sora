package lmtpproxy

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/migadu/sora/server"
)

// errXCLIENTRefused is the backend refusing XCLIENT at a command boundary (5xx or a
// non-421 4xx reply, such as go-smtp's 451 when the XCLIENT hook denies forwarding).
// The full single- or multi-line reply was read, so the stream is at a command boundary
// and the transaction can go on without the forwarding parameters. Any other error of
// the exchange (I/O, timeout, 421 closing transmission channel, malformed/unexpected
// status, or a failed post-220 LHLO) leaves the connection unusable for MAIL FROM.
var errXCLIENTRefused = errors.New("backend rejected XCLIENT command")

// parseSMTPReplyLine parses one CR/LF-trimmed SMTP/LMTP reply line per RFC 5321 §4.2,
// returning its 3-digit status code, whether it is a continuation line ('-'), and
// whether the line has a valid status code boundary (end-of-line, ' ', or '-').
func parseSMTPReplyLine(line string) (code string, cont bool, ok bool) {
	if len(line) < 3 {
		return "", false, false
	}
	for i := 0; i < 3; i++ {
		if line[i] < '0' || line[i] > '9' {
			return "", false, false
		}
	}
	if len(line) == 3 {
		return line, false, true
	}
	switch line[3] {
	case ' ':
		return line[:3], false, true
	case '-':
		return line[:3], true, true
	default:
		return "", false, false
	}
}

// readSMTPReply reads a complete single- or multi-line SMTP/LMTP reply from reader,
// bounded per line by backendResponseLineMax and in line count by maxLHLOResponseLines.
func readSMTPReply(reader *bufio.Reader) (code string, lines []string, err error) {
	for i := 0; i < maxLHLOResponseLines; i++ {
		raw, err := server.ReadBoundedLine(reader, backendResponseLineMax)
		if err != nil {
			return "", nil, err
		}
		line := strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r")
		lineCode, cont, ok := parseSMTPReplyLine(line)
		if !ok {
			return "", nil, fmt.Errorf("malformed reply line %q", line)
		}
		if i == 0 {
			code = lineCode
		} else if lineCode != code {
			return "", nil, fmt.Errorf("inconsistent multiline reply code %s after %s in %q", lineCode, code, line)
		}
		lines = append(lines, line)
		if !cont {
			return code, lines, nil
		}
	}
	return "", nil, fmt.Errorf("reply exceeded %d lines", maxLHLOResponseLines)
}

// sendForwardingParametersToBackend sends an XCLIENT command to the backend server
// with forwarding parameters containing the real client information
func (s *Session) sendForwardingParametersToBackend(writer *bufio.Writer, reader *bufio.Reader) error {
	// Create forwarding parameters using the helper function.
	// Pass proxyInfo if available from PROXY protocol header.
	// NewForwardingParams will extract real client IP from PROXY protocol or connection.
	forwardingParams := server.NewForwardingParams(s.clientConn, s.proxyInfo)

	// No session ID: Postfix's XCLIENT has no attribute for it (XCLIENT_README: NAME, ADDR,
	// PORT, PROTO, HELO, LOGIN, DESTADDR, DESTPORT). Dovecot's adds SESSION, but the Sora
	// LMTP backend (go-smtp) advertises only ADDR PORT PROTO HELO LOGIN NAME and answers any
	// other attribute with 501, refusing the whole XCLIENT. The session ID reaches the
	// backend in the PROXY v2 header (TLV 0xE1).
	//
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
		return fmt.Errorf("failed to write XCLIENT command: %w", err)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush XCLIENT command: %w", err)
	}

	// Set a deadline for reading the response (and any post-reset LHLO) to prevent hanging.
	readTimeout := s.server.connManager.GetConnectTimeout()
	if readTimeout > 0 {
		if err := s.backendConn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return fmt.Errorf("failed to set read deadline for XCLIENT response: %w", err)
		}
		// Ensure the deadline is cleared when the function returns.
		defer func() {
			if err := s.backendConn.SetReadDeadline(time.Time{}); err != nil {
				s.DebugLog("failed to clear read deadline after XCLIENT", "error", err)
			}
		}()
	}

	// Read full single- or multi-line XCLIENT reply so no continuation/final lines stay
	// buffered for MAIL FROM or post-XCLIENT LHLO.
	code, lines, err := readSMTPReply(reader)
	if err != nil {
		return fmt.Errorf("failed to read XCLIENT response: %w", err)
	}
	finalLine := lines[len(lines)-1]

	switch {
	case code == "250":
		s.DebugLog("XCLIENT forwarding completed", "params", xclientParams)

	case code == "220":
		// XCLIENT succeeded - server reset session and sent new greeting
		s.DebugLog("XCLIENT accepted - server reset session", "greeting", finalLine)

		// After XCLIENT, the session resets and we need to send LHLO again
		lhloCommand := fmt.Sprintf("LHLO %s\r\n", s.server.hostname)
		if _, err := writer.WriteString(lhloCommand); err != nil {
			return fmt.Errorf("failed to write LHLO after XCLIENT: %w", err)
		}
		if err := writer.Flush(); err != nil {
			return fmt.Errorf("failed to flush LHLO after XCLIENT: %w", err)
		}

		// Read full LHLO response and verify 250 acceptance; the read deadline set above still applies.
		lhloCode, lhloLines, err := readSMTPReply(reader)
		if err != nil {
			return fmt.Errorf("failed to read LHLO response after XCLIENT: %w", err)
		}
		for _, lhloLine := range lhloLines {
			s.DebugLog("backend LHLO after XCLIENT", "response", lhloLine)
		}
		if lhloCode != "250" {
			return fmt.Errorf("backend LHLO after XCLIENT failed: %s", lhloLines[len(lhloLines)-1])
		}

		// Session reset discarded prior ESMTP state; refresh capabilities from the new LHLO.
		s.backendSMTPUTF8, s.backendSIZE = false, false
		for _, lhloLine := range lhloLines {
			if isSMTPUTF8Capability(lhloLine) {
				s.backendSMTPUTF8 = true
			}
			if isSIZECapability(lhloLine) {
				s.backendSIZE = true
			}
		}

		s.DebugLog("XCLIENT and session reset completed")

	case code == "421":
		// RFC 5321 §4.2.1: service shutting down, closing transmission channel.
		return fmt.Errorf("backend closing connection on XCLIENT: %s", finalLine)

	case code[0] == '4' || code[0] == '5':
		return fmt.Errorf("%w: %s", errXCLIENTRefused, finalLine)

	default:
		return fmt.Errorf("unexpected XCLIENT response: %s", finalLine)
	}

	return nil
}
