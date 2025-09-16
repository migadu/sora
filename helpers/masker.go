package helpers

import "strings"

// MaskSensitive redacts sensitive information from a log line for specific commands.
// It is designed to hide passwords or other credentials from commands like LOGIN or AUTHENTICATE.
// It correctly handles both tagged (IMAP) and untagged (ManageSieve) protocols.
func MaskSensitive(line, command string, sensitiveCommands ...string) string {
	isSensitive := false
	for _, cmd := range sensitiveCommands {
		if strings.EqualFold(command, cmd) {
			isSensitive = true
			break
		}
	}

	if !isSensitive {
		return line
	}

	parts := strings.Fields(line)
	if len(parts) < 1 {
		return line
	}

	// Find the index of the command within the line parts
	cmdIndex := -1
	for i, p := range parts {
		if strings.EqualFold(p, command) {
			cmdIndex = i
			break
		}
	}

	if cmdIndex == -1 {
		return line // Cannot determine command position, return original line
	}

	// For LOGIN, we expect: <tag> LOGIN <user> <pass>. Redact after <user>.
	// For AUTHENTICATE, we expect: <tag> AUTHENTICATE <mech> <data>. Redact after <mech>.
	// For POP3 PASS, we expect: PASS <pass>. Redact after PASS.
	var partsToKeepCount int
	if strings.EqualFold(command, "PASS") {
		partsToKeepCount = cmdIndex + 1
	} else {
		// Default for LOGIN, AUTHENTICATE, etc.
		partsToKeepCount = cmdIndex + 2
	}

	// If the line has more parts than we want to keep, redact the rest.
	if len(parts) > partsToKeepCount {
		return strings.Join(parts[:partsToKeepCount], " ") + " [REDACTED]"
	}

	// If the line has exactly the number of parts to keep or fewer, it's safe to log.
	// e.g., "A001 AUTHENTICATE PLAIN" where the data comes on the next line.
	return line
}
