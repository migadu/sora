// Package pop3 implements a POP3 (Post Office Protocol version 3) server.
//
// This package provides a production-ready POP3 server with:
//   - RFC 1939 POP3 core protocol
//   - RFC 1734 POP3 authentication (SASL)
//   - TLS/STLS support
//   - UIDL (Unique ID Listing) support
//   - Top command for message previews
//   - Message deletion tracking
//
// # POP3 Protocol
//
// POP3 is a simple protocol for retrieving mail from a server.
// Unlike IMAP, POP3 typically downloads and deletes messages,
// though the DELE command can be used to mark messages for deletion
// without removing them until QUIT is issued.
//
// # Server States
//
//	AUTHORIZATION → TRANSACTION → UPDATE
//
// # Starting a POP3 Server
//
//	cfg := &config.POP3Config{
//		Addr:    ":110",
//		TLSAddr: ":995",
//		MaxConnections: 500,
//	}
//	srv, err := pop3.NewServer(cfg, db, s3, cache)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Start listeners
//	go srv.ListenAndServe(ctx)
//	go srv.ListenAndServeTLS(ctx, certFile, keyFile)
//
// # Supported Commands
//
// Authorization:
//   - USER: Specify username
//   - PASS: Provide password
//   - QUIT: End session
//   - STLS: Upgrade to TLS
//
// Transaction:
//   - STAT: Get mailbox statistics
//   - LIST: List message sizes
//   - RETR: Retrieve a message
//   - DELE: Mark message for deletion
//   - NOOP: No operation (keepalive)
//   - RSET: Unmark deleted messages
//   - TOP: Get message headers + n lines
//   - UIDL: Get unique message IDs
//
// # Message Deletion
//
// Messages marked with DELE are only deleted when the session
// ends normally with QUIT. If the connection is closed abnormally,
// deletions are not applied.
//
// # UIDL Support
//
// The UIDL command provides unique, persistent identifiers for
// messages, allowing clients to avoid downloading the same message
// multiple times across sessions.
package pop3
