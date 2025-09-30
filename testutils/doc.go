// Package testutils provides testing utilities for the Sora mail server project.
//
// This package contains mocks, test helpers, and other utilities that can be
// shared across different test suites in the project.
//
// Key components:
//   - MockS3Storage: A full-featured S3 storage mock for testing
//   - Test helpers for database setup, cleanup, and other common operations
//
// Example usage:
//
//	import "github.com/migadu/sora/testutils"
//
//	func TestMyFunction(t *testing.T) {
//		mockS3 := testutils.NewMockS3Storage()
//		// Use mockS3 in your tests...
//	}
package testutils
