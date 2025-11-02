// Package sieveengine implements a SIEVE email filtering engine.
//
// SIEVE (RFC 5228) is a language for filtering email messages at delivery time.
// This package provides:
//   - RFC 5228 SIEVE base specification
//   - RFC 5230 vacation extension
//   - fileinto, reject, discard, keep actions
//   - address, envelope, header tests
//   - Vacation response tracking (prevents loops)
//
// # SIEVE Language
//
// SIEVE scripts are written in a simple, safe scripting language:
//
//	require ["fileinto", "vacation", "envelope"];
//
//	# Rule 1: File work emails
//	if address :is "from" "boss@company.com" {
//	    fileinto "Work";
//	    stop;
//	}
//
//	# Rule 2: Vacation response
//	if not header :contains "X-Spam-Flag" "YES" {
//	    vacation :days 7 :subject "Out of office"
//	             "I'm on vacation until next Monday.";
//	}
//
//	# Rule 3: Spam to Junk
//	if header :contains "X-Spam-Flag" "YES" {
//	    fileinto "Junk";
//	}
//
// # Execution Model
//
// SIEVE scripts are executed during LMTP delivery:
//  1. Parse and validate script
//  2. Execute tests in order
//  3. Perform matched actions
//  4. Implicit "keep" if no explicit action
//
// # Supported Tests
//
//   - address: Test email addresses
//   - envelope: Test SMTP envelope
//   - header: Test message headers
//   - true/false: Always succeed/fail
//   - not, allof, anyof: Logical operators
//
// # Supported Actions
//
//   - fileinto: Deliver to specific mailbox
//   - redirect: Forward to another address
//   - keep: Keep in INBOX (default)
//   - discard: Delete message
//   - reject: Reject with error message
//   - stop: Stop script execution
//   - vacation: Send auto-reply
//
// # Vacation Tracking
//
// To prevent mail loops, vacation responses are tracked in the database.
// A response is sent once per sender within the :days period.
//
// # Safety Features
//
//   - No infinite loops (execution limits)
//   - No file system access
//   - No network access
//   - No arbitrary code execution
//   - Safe string operations
//
// # Usage
//
//	script := `
//	require ["fileinto"];
//	if header :contains "subject" "[URGENT]" {
//	    fileinto "Important";
//	}
//	`
//
//	env := sieveengine.NewEnv(AccountID, messageData)
//	result, err := sieveengine.Execute(script, env)
//	if err != nil {
//		// Script error
//	}
//
//	// Apply result actions
//	if result.Mailbox != "" {
//		deliverToMailbox(result.Mailbox)
//	}
package sieveengine
