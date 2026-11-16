package storage

import (
	"errors"
	"fmt"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
)

// DeleteOutcomeUnknown preserves an uncertain earlier request even if a retry
// subsequently succeeds. That earlier request could still arrive at storage.
type DeleteOutcomeUnknown struct{ Err error }

func (e *DeleteOutcomeUnknown) Error() string {
	return fmt.Sprintf("earlier storage DELETE outcome is unknown: %v", e.Err)
}
func (e *DeleteOutcomeUnknown) Unwrap() error { return e.Err }

type DeleteNotAttempted struct{ Err error }

func (e *DeleteNotAttempted) Error() string { return e.Err.Error() }
func (e *DeleteNotAttempted) Unwrap() error { return e.Err }

type DeleteObjectError struct{ Code, Message string }

func (e *DeleteObjectError) Error() string {
	return fmt.Sprintf("S3 delete error: %s - %s", e.Code, e.Message)
}

// DeleteDefinitelyRefused is deliberately narrow: a cancellation, timeout, server
// error or unknown earlier attempt cannot release a durable deletion fence.
func DeleteDefinitelyRefused(err error) bool {
	if err == nil {
		return false
	}
	var unknown *DeleteOutcomeUnknown
	if errors.As(err, &unknown) {
		return false
	}
	var notAttempted *DeleteNotAttempted
	if errors.As(err, &notAttempted) {
		return true
	}
	var response *awshttp.ResponseError
	if errors.As(err, &response) {
		switch response.HTTPStatusCode() {
		case 401, 403, 404, 405, 413, 414, 415, 416:
			return true
		}
	}
	code := ""
	var object *DeleteObjectError
	var api smithy.APIError
	if errors.As(err, &object) {
		code = object.Code
	} else if errors.As(err, &api) {
		code = api.ErrorCode()
	}
	switch code {
	case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "InvalidArgument", "InvalidRequest", "InvalidBucketName", "NoSuchBucket", "MethodNotAllowed":
		return true
	}
	return false
}
