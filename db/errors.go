package db

import "errors"

// Sentinel errors for database operations
var (
	// ErrAccountNotFound indicates that an account was not found in the database
	ErrAccountNotFound = errors.New("account not found")

	// ErrMailboxNotFound indicates that a mailbox was not found in the database
	ErrMailboxNotFound = errors.New("mailbox not found")

	// ErrMessageNotFound indicates that a message was not found in the database
	ErrMessageNotFound = errors.New("message not found")

	// ErrInvalidCredentials indicates that the provided credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrDuplicateAccount indicates that an account with the given email already exists
	ErrDuplicateAccount = errors.New("account already exists")

	// ErrDuplicateMailbox indicates that a mailbox with the given name already exists
	ErrDuplicateMailbox = errors.New("mailbox already exists")
)
