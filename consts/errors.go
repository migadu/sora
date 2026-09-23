package consts

import "errors"

var (
	ErrMailboxNotFound        = errors.New("mailbox not found")
	ErrMailboxInvalidName     = errors.New("invalid mailbox name")
	ErrMailboxAlreadyExists   = errors.New("mailbox already exists")
	ErrMailboxSpecialUseInUse = errors.New("special-use attribute already assigned")
	ErrUserNotFound           = errors.New("user not found")
	ErrAccountAlreadyExists   = errors.New("account already exists")
	ErrInternalError          = errors.New("internal error")
	ErrNotPermitted           = errors.New("operation not permitted")
	ErrMessageExists          = errors.New("message already exists")
	ErrMalformedMessage       = errors.New("malformed message")
	ErrMessageNotAvailable    = errors.New("message not available")
	ErrEmptyMessageID         = errors.New("empty message ID")
	ErrTooManyKeywords        = errors.New("too many keywords on a message")
	ErrInvalidFlag            = errors.New("not a valid IMAP flag")
	ErrAuthenticationFailed   = errors.New("authentication failed")

	ErrDBNotFound        = errors.New("not found")
	ErrDBUniqueViolation = errors.New("unique violation")
	// ErrUIDConflict is a unique violation on (mailbox_id, uid): a caller asked for a UID
	// that the mailbox already has (preserve-uids import onto a mailbox that moved on).
	// Distinct from ErrDBUniqueViolation because it is NOT "this message is already
	// there": the message was not stored and must be reported, not counted as a skip.
	ErrUIDConflict               = errors.New("uid conflict")
	ErrDBCommitTransactionFailed = errors.New("commit failed")
	ErrDBBeginTransactionFailed  = errors.New("start transaction failed")
	ErrDBQueryFailed             = errors.New("query failed")
	ErrDBInsertFailed            = errors.New("insert failed")
	ErrDBUpdateFailed            = errors.New("update failed")

	ErrS3UploadFailed = errors.New("s3 upload failed")

	ErrSerializationFailed = errors.New("serialization failed")
)
