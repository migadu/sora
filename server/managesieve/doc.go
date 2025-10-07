// Package managesieve implements a ManageSieve server for SIEVE script management.
//
// ManageSieve (RFC 5804) allows clients to upload, download, activate,
// and manage SIEVE filtering scripts on the server. This package provides:
//   - RFC 5804 ManageSieve protocol
//   - SIEVE script validation
//   - TLS/STARTTLS support
//   - SASL authentication
//   - Script activation/deactivation
//   - UTF-8 support
//
// # ManageSieve Protocol
//
// ManageSieve is a protocol for remotely managing SIEVE scripts.
// Users can upload filtering rules without direct server access.
//
// # Starting a ManageSieve Server
//
//	cfg := &config.ManageSieveConfig{
//		Addr: ":4190",
//		MaxConnections: 100,
//	}
//	srv, err := managesieve.NewServer(cfg, db)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	go srv.ListenAndServe(ctx)
//
// # Supported Commands
//
//   - AUTHENTICATE: Authenticate user
//   - STARTTLS: Upgrade to TLS
//   - CAPABILITY: List server capabilities
//   - HAVESPACE: Check script size limits
//   - PUTSCRIPT: Upload a script
//   - LISTSCRIPTS: List available scripts
//   - SETACTIVE: Activate a script
//   - GETSCRIPT: Download a script
//   - DELETESCRIPT: Remove a script
//   - RENAMESCRIPT: Rename a script
//   - CHECKSCRIPT: Validate script syntax
//
// # SIEVE Script Validation
//
// All uploaded scripts are validated before storage to prevent
// syntax errors during message delivery. Invalid scripts are
// rejected with detailed error messages.
//
// # Integration with LMTP
//
// When a message is delivered via LMTP, the active SIEVE script
// (if any) is executed. The script can:
//   - File messages into specific folders (fileinto)
//   - Reject messages (reject)
//   - Send vacation responses (vacation)
//   - Discard messages (discard)
//
// # Example SIEVE Script
//
//	require ["fileinto", "vacation"];
//
//	# File work emails
//	if address :is "from" "boss@work.com" {
//	    fileinto "Work";
//	}
//
//	# Vacation response
//	vacation :days 7 "I'm on vacation until next week";
package managesieve
