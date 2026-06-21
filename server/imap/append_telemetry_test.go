package imap

import (
	"io"
	"net"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestClassifyAndTrackError_Hardened(t *testing.T) {
	// Initialize a dummy session
	s := &IMAPSession{}

	tests := []struct {
		name              string
		err               error
		imapErr           *imap.Error
		expectedErrorType string
		expectedSeverity  string
	}{
		{
			name:              "Unexpected EOF maps to client network_error",
			err:               io.ErrUnexpectedEOF,
			imapErr:           nil,
			expectedErrorType: "network_error",
			expectedSeverity:  "client_error",
		},
		{
			name:              "Unavailable response code maps to service_unavailable",
			err:               nil,
			imapErr:           &imap.Error{Code: imap.ResponseCodeUnavailable},
			expectedErrorType: "service_unavailable",
			expectedSeverity:  "server_error",
		},
		{
			name:              "Net timeout maps to client network_timeout",
			err:               &net.OpError{Op: "read", Err: &mockTimeoutError{}},
			imapErr:           nil,
			expectedErrorType: "network_timeout",
			expectedSeverity:  "client_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics.ProtocolErrors.Reset()
			s.classifyAndTrackError("APPEND", tt.err, tt.imapErr)

			count := testutil.ToFloat64(metrics.ProtocolErrors.WithLabelValues("imap", "APPEND", tt.expectedErrorType, tt.expectedSeverity))
			if count != 1 {
				t.Errorf("Expected metric count 1 for type %q, severity %q, got %f",
					tt.expectedErrorType, tt.expectedSeverity, count)
			}
		})
	}
}

type mockTimeoutError struct{}

func (e *mockTimeoutError) Error() string   { return "timeout" }
func (e *mockTimeoutError) Timeout() bool   { return true }
func (e *mockTimeoutError) Temporary() bool { return true }
