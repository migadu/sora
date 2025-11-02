package testutils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileBased S3Mock implements a disk-based S3 storage mock for testing
// It acts like S3 but stores files in a temporary directory
type FileBasedS3Mock struct {
	mu      sync.RWMutex
	baseDir string
	errors  map[string]error // Map of key -> error to simulate failures
}

// NewFileBasedS3Mock creates a new file-based S3 mock using a temporary directory
func NewFileBasedS3Mock(baseDir string) (*FileBasedS3Mock, error) {
	// Create the base directory if it doesn't exist
	err := os.MkdirAll(baseDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &FileBasedS3Mock{
		baseDir: baseDir,
		errors:  make(map[string]error),
	}, nil
}

// Put stores an object in the mock storage (as a file on disk)
func (m *FileBasedS3Mock) Put(key string, reader io.Reader, size int64) error {
	// Check for simulated error (with lock)
	m.mu.RLock()
	err, hasError := m.errors[key]
	m.mu.RUnlock()

	if hasError {
		return err
	}

	// Create the file path
	filePath := m.keyToFilePath(key)
	dirPath := filepath.Dir(filePath)

	// Use write lock for directory creation to prevent race conditions
	// when multiple threads try to create the same parent directory
	m.mu.Lock()
	err = os.MkdirAll(dirPath, 0755)
	m.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create the file (different keys write to different files, so no lock needed here)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy data from reader to file
	written, err := io.Copy(file, reader)
	if err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Verify size matches
	if written != size {
		return fmt.Errorf("size mismatch: expected %d, wrote %d", size, written)
	}

	return nil
}

// Get retrieves an object from the mock storage
func (m *FileBasedS3Mock) Get(key string) (io.ReadCloser, error) {
	// Check for simulated error (with lock)
	m.mu.RLock()
	err, hasError := m.errors[key]
	m.mu.RUnlock()

	if hasError {
		return nil, err
	}

	filePath := m.keyToFilePath(key)

	// Check if file exists (no lock needed - file system handles this)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("object not found: %s", key)
	}

	// Open the file (no lock needed - OS handles concurrent reads)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

// Exists checks if an object exists in the mock storage
func (m *FileBasedS3Mock) Exists(key string) (bool, string, error) {
	// Check for simulated error (with lock)
	m.mu.RLock()
	err, hasError := m.errors[key]
	m.mu.RUnlock()

	if hasError {
		return false, "", err
	}

	filePath := m.keyToFilePath(key)

	// Check if file exists (no lock needed - file system handles this)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, "", nil
	} else if err != nil {
		return false, "", fmt.Errorf("failed to stat file: %w", err)
	}

	// Return mock version ID
	return true, "mock-version-id", nil
}

// Delete removes an object from the mock storage
func (m *FileBasedS3Mock) Delete(key string) error {
	// Check for simulated error (with lock)
	m.mu.RLock()
	err, hasError := m.errors[key]
	m.mu.RUnlock()

	if hasError {
		return err
	}

	filePath := m.keyToFilePath(key)

	// Remove the file (ignore if it doesn't exist, no lock needed - OS handles this)
	err = os.Remove(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

// Copy copies an object within the mock storage
func (m *FileBasedS3Mock) Copy(sourcePath, destPath string) error {
	// Check for simulated error (with lock)
	m.mu.RLock()
	err, hasError := m.errors[sourcePath]
	m.mu.RUnlock()

	if hasError {
		return err
	}

	sourceFilePath := m.keyToFilePath(sourcePath)
	destFilePath := m.keyToFilePath(destPath)

	// Check if source exists (no lock needed - file system handles this)
	if _, err := os.Stat(sourceFilePath); os.IsNotExist(err) {
		return fmt.Errorf("source object not found: %s", sourcePath)
	}

	// Create destination directory (no lock needed - OS handles concurrency)
	err = os.MkdirAll(filepath.Dir(destFilePath), 0755)
	if err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Copy file (no lock needed - different files)
	sourceFile, err := os.Open(sourceFilePath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(destFilePath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	return nil
}

// EnableEncryption is a no-op for the mock (encryption can be tested separately)
func (m *FileBasedS3Mock) EnableEncryption(encryptionKey string) error {
	// Mock implementation - just validate the key format
	if encryptionKey == "" {
		return fmt.Errorf("encryption key is required when encryption is enabled")
	}
	if len(encryptionKey) != 64 { // 32 bytes as 64 hex characters
		return fmt.Errorf("encryption key must be 32 bytes (64 hex characters)")
	}
	return nil
}

// Test helper methods

// SetError configures the mock to return an error for operations on a specific key
func (m *FileBasedS3Mock) SetError(key string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[key] = err
}

// ClearError removes any configured error for a specific key
func (m *FileBasedS3Mock) ClearError(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.errors, key)
}

// GetStoredKeys returns all keys that have been stored
func (m *FileBasedS3Mock) GetStoredKeys() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string

	// Walk the directory tree to find all files
	err := filepath.Walk(m.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			// Convert file path back to S3 key
			key := m.filePathToKey(path)
			keys = append(keys, key)
		}

		return nil
	})

	if err != nil {
		return []string{} // Return empty slice on error
	}

	return keys
}

// GetStoredData returns the data for a specific key (for testing)
func (m *FileBasedS3Mock) GetStoredData(key string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filePath := m.keyToFilePath(key)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false
	}

	return data, true
}

// Clear removes all stored objects and errors
func (m *FileBasedS3Mock) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove all files in the base directory
	os.RemoveAll(m.baseDir)
	os.MkdirAll(m.baseDir, 0755)

	// Clear error map
	m.errors = make(map[string]error)
}

// ObjectCount returns the number of stored objects
func (m *FileBasedS3Mock) ObjectCount() int {
	return len(m.GetStoredKeys())
}

// GetBaseDir returns the base directory path (useful for debugging)
func (m *FileBasedS3Mock) GetBaseDir() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.baseDir
}

// Helper methods

// keyToFilePath converts an S3 key to a file path
func (m *FileBasedS3Mock) keyToFilePath(key string) string {
	// Replace any problematic characters and ensure proper path structure
	safePath := strings.ReplaceAll(key, "/", string(os.PathSeparator))
	return filepath.Join(m.baseDir, safePath)
}

// filePathToKey converts a file path back to an S3 key
func (m *FileBasedS3Mock) filePathToKey(filePath string) string {
	// Remove base directory and convert to S3 key format
	relPath, err := filepath.Rel(m.baseDir, filePath)
	if err != nil {
		return filePath // Fallback to original path
	}

	// Convert path separators to forward slashes (S3 standard)
	return strings.ReplaceAll(relPath, string(os.PathSeparator), "/")
}
