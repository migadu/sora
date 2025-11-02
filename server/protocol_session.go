package server

import (
	"context"
)

// ProtocolSession defines a common interface for all protocol sessions
// This allows us to standardize functionality across different protocols
type ProtocolSession interface {
	// GetID returns the unique identifier for this session
	GetID() string

	// GetAccountID returns the user ID associated with this session, or 0 if not authenticated
	GetAccountID() int64

	// GetProtocol returns the protocol name (e.g., "IMAP", "LMTP", "ManageSieve")
	GetProtocol() string

	// GetRemoteIP returns the client's IP address
	GetRemoteIP() string

	// GetContext returns the session's context
	GetContext() context.Context

	// IsAuthenticated returns whether the session is authenticated
	IsAuthenticated() bool

	// Close terminates the session and cleans up resources
	Close() error

	// Log logs a message with the given format and arguments
	Log(format string, args ...any)
}

// BaseProtocolSession provides default implementations for the ProtocolSession interface
// Protocol-specific implementations can embed this struct to inherit these methods
type BaseProtocolSession struct {
	Session
}

// GetID returns the unique identifier for this session
func (s *BaseProtocolSession) GetID() string {
	return s.Id
}

// GetAccountID returns the user ID associated with this session, or 0 if not authenticated
func (s *BaseProtocolSession) GetAccountID() int64 {
	if s.User == nil {
		return 0
	}
	return s.User.AccountID()
}

// GetProtocol returns the protocol name
func (s *BaseProtocolSession) GetProtocol() string {
	return s.Protocol
}

// GetRemoteIP returns the client's IP address
func (s *BaseProtocolSession) GetRemoteIP() string {
	return s.RemoteIP
}

// GetContext returns the session's context
func (s *BaseProtocolSession) GetContext() context.Context {
	// This must be implemented by the embedding struct as we don't store context here
	return nil
}

// IsAuthenticated returns whether the session is authenticated
func (s *BaseProtocolSession) IsAuthenticated() bool {
	return s.User != nil
}

// HandleSessionError handles a session error and optionally returns a protocol-specific error
func HandleSessionError(session ProtocolSession, err error, message string) error {
	if err != nil {
		session.Log("[%s] %s: %v", session.GetProtocol(), message, err)
	}
	return err
}
