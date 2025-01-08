package consts

import "errors"

var (
	ErrMailboxNotFound      = errors.New("mailbox not found")
	ErrMailboxInvalidName   = errors.New("invalid mailbox name")
	ErrMailboxAlreadyExists = errors.New("mailbox already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrInternalError        = errors.New("internal error")
	ErrNotPermitted         = errors.New("operation not permitted")
	ErrMessageExists        = errors.New("message already exists")
	ErrMalformedMessage     = errors.New("malformed message")

	ErrDBNotFound                = errors.New("not found")
	ErrDBUniqueViolation         = errors.New("unique violation")
	ErrDBCommitTransactionFailed = errors.New("commit failed")
	ErrDBBeginTransactionFailed  = errors.New("start transaction failed")
	ErrDBQueryFailed             = errors.New("query failed")
	ErrDBInsertFailed            = errors.New("insert failed")
	ErrDBUpdateFailed            = errors.New("update failed")

	ErrS3UploadFailed = errors.New("s3 upload failed")

	ErrSerializationFailed = errors.New("serialization failed")
)
