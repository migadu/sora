package main

import "io"

// objectStorage defines the interface for S3-compatible object storage operations.
// This allows for using either real S3 storage or file-based mocks during testing.
// Both storage.S3Storage and testutils.FileBasedS3Mock implement this interface.
type objectStorage interface {
	Put(key string, reader io.Reader, size int64) error
	Get(key string) (io.ReadCloser, error)
	Exists(key string) (bool, string, error)
	Delete(key string) error
	Copy(sourcePath, destPath string) error
	EnableEncryption(encryptionKey string) error
}
