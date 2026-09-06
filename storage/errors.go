package storage

import "errors"

// Sentinel errors for storage operations.
// These errors can be checked using errors.Is() for proper error handling.

var (
	// ErrRetrieveFailed indicates that retrieval from storage failed
	ErrRetrieveFailed = errors.New("failed to retrieve message from storage")

	// ErrEmptyData indicates that storage returned empty data
	ErrEmptyData = errors.New("storage returned empty data")

	// ErrCorruptObject indicates that an object was fetched but cannot be decoded (its
	// ciphertext fails authentication, or is too short). It is a property of the stored
	// bytes, not of the storage service: it must neither be retried nor counted against
	// the circuit breaker, and readers treat it as permanent.
	ErrCorruptObject = errors.New("stored object is corrupt")
)
