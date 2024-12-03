// storage/s3_storage.go
package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/emersion/go-message"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Storage struct {
	Client     *minio.Client
	BucketName string
}

func NewS3Storage(endpoint, accessKeyID, secretAccessKey, bucketName string, useSSL bool) (*S3Storage, error) {
	// Initialize the MinIO client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL, // Use SSL (https) if true
	})
	if err != nil {
		log.Fatalln(err)
		return nil, err
	}

	// Enable detailed tracing of requests and responses for debugging
	client.TraceOn(os.Stdout)

	// Return the initialized storage client
	return &S3Storage{
		Client:     client,
		BucketName: bucketName,
	}, nil
}

func (s *S3Storage) SaveMessage(key string, body io.Reader, size int64) error {
	_, err := s.Client.PutObject(context.Background(), s.BucketName, key, body, size, minio.PutObjectOptions{})
	return err
}

func (s *S3Storage) GetMessage(key string) (io.ReadCloser, error) {
	object, err := s.Client.GetObject(context.Background(), s.BucketName, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	return object, nil
}

func (s *S3Storage) DeleteMessage(key string) error {
	return s.Client.RemoveObject(context.Background(), s.BucketName, key, minio.RemoveObjectOptions{})
}

// StoreMessagePart uploads the message part to the S3-compatible storage using an io.Reader for binary data
func (s *S3Storage) SaveMessagePart(path string, partContent io.Reader, size int64) error {
	// Upload the message part to the S3-compatible storage as a stream
	_, err := s.Client.PutObject(context.Background(), s.BucketName, path, partContent, size, minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("failed to upload message part to S3: %v", err)
	}

	return nil
}

func (s *S3Storage) CopyMessagePart(srcKey, destKey string) error {
	// Define source and destination options
	src := minio.CopySrcOptions{
		Bucket: s.BucketName,
		Object: srcKey,
	}

	dest := minio.CopyDestOptions{
		Bucket: s.BucketName,
		Object: destKey,
	}

	// Perform the S3 copy operation
	_, err := s.Client.CopyObject(context.Background(), dest, src)
	if err != nil {
		return fmt.Errorf("failed to copy object from %s to %s: %v", srcKey, destKey, err)
	}

	return nil
}

// GetMessagePart retrieves a message part as an io.Reader (binary stream) from S3-compatible storage
func (s *S3Storage) GetMessagePart(path string) (io.Reader, error) {
	object, err := s.Client.GetObject(context.Background(), s.BucketName, path, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve message part from S3: %v", err)
	}
	return object, nil
}

func (s *S3Storage) CopyMessage(sourcePath, destPath string) error {
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
		return fmt.Errorf("failed to copy object from %s to %s: %v", sourcePath, destPath, err)
	}
	return nil
}

func (s *S3Storage) SaveHeadersAndParts(ctx context.Context, m *message.Entity, baseKey string) error {
	var headerBuf bytes.Buffer

	// Iterate over all header fields using m.Header.Fields
	for field := m.Header.Fields(); field.Next(); {
		key := field.Key()
		value := field.Value()

		// Write each header field into the buffer
		_, err := headerBuf.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		if err != nil {
			return fmt.Errorf("failed to write headers: %v", err)
		}
	}

	headerBuf.WriteString("\n")

	headerKey := baseKey + "/headers"
	err := s.SaveMessagePart(headerKey, &headerBuf, int64(headerBuf.Len()))
	if err != nil {
		return fmt.Errorf("failed to upload headers to S3: %v", err)
	}

	if mr := m.MultipartReader(); mr != nil {
		partNumber := 1
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("failed to read next part: %v", err)
			}

			// Read part content and upload to S3
			var buf bytes.Buffer
			size, err := io.Copy(&buf, part.Body)
			if err != nil {
				return fmt.Errorf("failed to read part content: %v", err)
			}

			partKey := fmt.Sprintf("%s/part%d", baseKey, partNumber)
			err = s.SaveMessagePart(partKey, &buf, size)
			if err != nil {
				return fmt.Errorf("failed to upload part to S3: %v", err)
			}

			partNumber++
		}
	} else {
		// Non-multipart message, save full message as one part
		var buf bytes.Buffer
		size, err := io.Copy(&buf, m.Body)
		if err != nil {
			return fmt.Errorf("failed to read message content: %v", err)
		}

		fullKey := baseKey + "/full"
		err = s.SaveMessagePart(fullKey, &buf, size)
		if err != nil {
			return fmt.Errorf("failed to upload full message to S3: %v", err)
		}
	}

	return nil
}
