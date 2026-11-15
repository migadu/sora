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
//   - reject, ereject: RFC 5429; treated as discard, so no bounce is ever sent
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
//	compiled, err := sieveengine.CompileScript(script, sieveengine.DefaultSieveExtensions)
//	if err != nil {
//		// Script does not compile: keep the message
//	}
//	executor := compiled.NewExecutor(accountID, vacationOracle, redirectOracle, rateLimit, rateWindow, maxHops)
//	result, err := executor.Evaluate(ctx, sieveengine.Context{ /* envelope, header, message */ })
//	if err != nil {
//		// Script error: implicit keep (RFC 5228 §2.10.6)
//	}
//
//	// Apply result actions. Write every redirect to the relay queue first, but hand
//	// it to the relay worker only once the delivery can no longer fail: a store that
//	// fails is retried by the sender, and a redirect handed over before it would go
//	// out again on every retry. A target the queue cannot take keeps the message in
//	// INBOX when nothing else stores it (RFC 5228 §4.2).
//	commit, abort, allHeld := holdRedirects(result.RedirectTo) // RelayQueue.Hold each
//	defer abort() // drops whatever was not handed over
//	dests := result.Destinations(!allHeld)
//	if len(dests) == 0 { // a redirect without :copy: nothing to store
//		if commit() {
//			return nil
//		}
//		dests = result.Destinations(true) // keep it after all
//	}
//	for _, dest := range dests {
//		if err := deliverToMailbox(dest.Mailbox); err != nil {
//			return err // nothing handed over yet
//		}
//	}
//	commit()
package sieveengine
