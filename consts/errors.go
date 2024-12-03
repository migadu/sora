package consts

import "errors"

var (
	ErrMailboxNotFound  = errors.New("mailbox not found")
	ErrUserNotFound     = errors.New("user not found")
	ErrInternalError    = errors.New("internal error")
	ErrNotPermitted     = errors.New("operation not permitted")
	ErrMessageExists    = errors.New("message already exists")
	ErrMalformedMessage = errors.New("malformed message")

	ErrDBNotFound                = errors.New("not found")
	ErrDBUniqueViolation         = errors.New("unique violation")
	ErrDBCommitTransactionFailed = errors.New("commit failed")
	ErrDBBeginTransactionFailed  = errors.New("start transaction failed")
	ErrDBInsertFailed            = errors.New("insert failed")

	ErrS3UploadFailed = errors.New("s3 upload failed")

	ErrSerializationFailed = errors.New("serialization failed")
)
