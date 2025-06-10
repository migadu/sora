// storage/s3_storage.go
package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Storage struct {
	Client        *minio.Client
	BucketName    string
	Encrypt       bool
	EncryptionKey []byte
}

func New(endpoint, accessKeyID, secretAccessKey, bucketName string, useSSL bool, debug bool) (*S3Storage, error) {
	// Initialize the MinIO client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL, // Use SSL (https) if true
	})
	if err != nil {
		log.Printf("[STORAGE] failed to initialize MinIO client: %v", err)
		return nil, fmt.Errorf("failed to initialize MinIO client: %w", err)
	}

	// Enable detailed tracing of requests and responses for debugging
	if debug {
		client.TraceOn(os.Stdout)
	}

	// Return the initialized storage client
	return &S3Storage{
		Client:     client,
		BucketName: bucketName,
		Encrypt:    false,
	}, nil
}

// EnableEncryption enables client-side encryption for S3 storage
func (s *S3Storage) EnableEncryption(encryptionKey string) error {
	if encryptionKey == "" {
		return fmt.Errorf("encryption key is required when encryption is enabled")
	}

	// Decode the hex-encoded encryption key
	masterKey, err := hex.DecodeString(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// Check if the key is 32 bytes (256 bits)
	if len(masterKey) != 32 {
		return fmt.Errorf("encryption key must be 32 bytes (64 hex characters)")
	}

	s.Encrypt = true
	s.EncryptionKey = masterKey
	log.Printf("[STORAGE] client-side encryption enabled")

	return nil
}

// Exists checks if an object with the given key exists in the bucket.
func (s *S3Storage) Exists(key string) (bool, string, error) {
	objInfo, err := s.Client.StatObject(context.Background(), s.BucketName, key, minio.StatObjectOptions{})
	if err == nil {
		return true, objInfo.VersionID, nil // Object exists
	}

	// Check if the error is a minio.ErrorResponse
	var minioErr minio.ErrorResponse
	if errors.As(err, &minioErr) {
		if minioErr.StatusCode == 404 {
			return false, "", nil // Object does not exist
		}
	}

	// Other error occurred
	return false, "", fmt.Errorf("failed to stat object %s: %w", key, err)
}

func (s *S3Storage) Put(key string, body io.Reader, size int64) error {
	exists, _, err := s.Exists(key)
	if err != nil {
		log.Printf("[STORAGE] error checking existence of object %s: %v", key, err)
		return err
	}
	if exists {
		log.Printf("[STORAGE] object %s already exists in S3, skipping upload.", key)
		return nil // Object already exists, no need to upload
	}

	// If encryption is enabled, encrypt the data before uploading
	if s.Encrypt {
		data, err := io.ReadAll(body)
		if err != nil {
			return fmt.Errorf("failed to read data for encryption: %w", err)
		}

		encryptedData, err := s.encryptData(data)
		if err != nil {
			return fmt.Errorf("failed to encrypt data: %w", err)
		}

		_, err = s.Client.PutObject(
			context.Background(),
			s.BucketName,
			key,
			bytes.NewReader(encryptedData),
			int64(len(encryptedData)),
			minio.PutObjectOptions{SendContentMd5: true},
		)
		return err
	}

	// No encryption, upload as-is
	_, err = s.Client.PutObject(
		context.Background(),
		s.BucketName,
		key,
		body,
		size,
		minio.PutObjectOptions{SendContentMd5: true},
	)
	return err
}

// encryptData encrypts data using AES-256-GCM
func (s *S3Storage) encryptData(plaintext []byte) ([]byte, error) {
	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(s.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Create a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES-256-GCM
func (s *S3Storage) decryptData(ciphertext []byte) ([]byte, error) {
	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(s.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract the nonce from the ciphertext
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// Decrypt the data
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (s *S3Storage) Get(key string) (io.ReadCloser, error) {
	object, err := s.Client.GetObject(context.Background(), s.BucketName, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}

	// If encryption is enabled, decrypt the data after downloading
	if s.Encrypt {
		encryptedData, err := io.ReadAll(object)
		if err != nil {
			return nil, fmt.Errorf("failed to read encrypted data: %w", err)
		}

		// Close the original reader since we've read all the data
		if err := object.Close(); err != nil {
			log.Printf("[STORAGE] WARNING: failed to close S3 object: %v", err)
		}

		decryptedData, err := s.decryptData(encryptedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}

		return io.NopCloser(bytes.NewReader(decryptedData)), nil
	}

	return object, nil
}

func (s *S3Storage) Delete(key string) error {
	// Check if the object exists before attempting to delete.
	// This makes DeleteMessage idempotent.
	exists, versionId, err := s.Exists(key)
	if err != nil {
		log.Printf("[STORAGE] error checking existence of object %s: %v", key, err)
		return err
	}
	if !exists {
		// Object does not exist, consider it successfully "deleted"
		log.Printf("[STORAGE] object %s does not exist in S3, skipping deletion.", key)
		return nil
	}
	return s.Client.RemoveObject(context.Background(), s.BucketName, key, minio.RemoveObjectOptions{VersionID: versionId})
}

func (s *S3Storage) Copy(sourcePath, destPath string) error {
	// If encryption is enabled, we need to download, decrypt, and re-upload
	if s.Encrypt {
		// Get the source object
		sourceObj, err := s.Get(sourcePath)
		if err != nil {
			return fmt.Errorf("failed to get source object for copy: %w", err)
		}
		defer sourceObj.Close()

		// Read all data (it's already decrypted by Get if encryption is enabled)
		data, err := io.ReadAll(sourceObj)
		if err != nil {
			return fmt.Errorf("failed to read source object data: %w", err)
		}

		// Put the data to the destination (it will be encrypted by Put if encryption is enabled)
		err = s.Put(destPath, bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return fmt.Errorf("failed to put data to destination: %w", err)
		}

		return nil
	}

	// No encryption, use the standard copy operation
	src := minio.CopySrcOptions{
		Bucket: s.BucketName,
		Object: sourcePath,
	}
	dst := minio.CopyDestOptions{
		Bucket: s.BucketName,
		Object: destPath,
	}

	_, err := s.Client.CopyObject(context.Background(), dst, src)
	if err != nil {
		return fmt.Errorf("failed to copy object from %s to %s: %w", sourcePath, destPath, err)
	}
	return nil
}
