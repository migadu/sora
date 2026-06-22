package resilient

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/migadu/sora/storage"
)

// awsResponseError builds an *awshttp.ResponseError carrying the given HTTP status,
// mirroring what the AWS SDK surfaces for S3 GET failures.
func awsResponseError(status int, msg string) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      errors.New(msg),
		},
	}
}

type mockAPIError struct {
	code    string
	message string
}

func (e *mockAPIError) Error() string                 { return fmt.Sprintf("api error %s: %s", e.code, e.message) }
func (e *mockAPIError) ErrorCode() string             { return e.code }
func (e *mockAPIError) ErrorMessage() string          { return e.message }
func (e *mockAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},

		// Permanent: object genuinely absent.
		{"NoSuchKey string", errors.New("operation error S3: GetObject, NoSuchKey: Key not found"), true},
		{"real B2 incident string", errors.New("https response error StatusCode: 404, RequestID: 855ff6, NoSuchKey: Key not found"), true},
		{"NotFound string", errors.New("NotFound: the specified key does not exist"), true},
		{"not found spaced", errors.New("the object was not found"), true},
		{"structured 404", awsResponseError(http.StatusNotFound, "NoSuchKey"), true},
		{"wrapped structured 404", fmt.Errorf("message UID 11: %w", awsResponseError(http.StatusNotFound, "gone")), true},
		{"double wrapped structured 404", fmt.Errorf("message UID 11: %w: %w", storage.ErrRetrieveFailed, awsResponseError(http.StatusNotFound, "NoSuchKey")), true},
		{"structured NoSuchKey", &mockAPIError{code: "NoSuchKey", message: "Key not found"}, true},
		{"structured NotFound", &mockAPIError{code: "NotFound", message: "Not found"}, true},

		// Transient: object should exist, S3 is just unreachable.
		{"connection refused", errors.New("dial tcp: connection refused"), false},
		{"timeout", errors.New("context deadline exceeded"), false},
		{"5xx", errors.New("operation error S3: GetObject, ServiceUnavailable: please retry"), false},
		{"structured 503", awsResponseError(http.StatusServiceUnavailable, "ServiceUnavailable"), false},
		{"circuit open", errors.New("circuit breaker is open"), false},
		{"panic recovered", errors.New("S3 get panicked: runtime error: invalid memory address"), false},
		{"structured NoSuchBucket", &mockAPIError{code: "NoSuchBucket", message: "Bucket not found"}, false},
		{"dns host not found", errors.New("dial tcp: lookup s3.amazonaws.com: host not found"), false},
		{"dns name not found", errors.New("dial tcp: lookup s3.amazonaws.com: name not found"), false},
		{"dns address not found", errors.New("dial tcp: lookup s3.amazonaws.com: address not found"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.err); got != tt.want {
				t.Errorf("IsNotFoundError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
