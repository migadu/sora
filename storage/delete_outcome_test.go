package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeleteRefusalDoesNotForgetUncertainty(t *testing.T) {
	refused := &DeleteObjectError{Code: "AccessDenied", Message: "denied"}
	require.True(t, DeleteDefinitelyRefused(fmt.Errorf("wrapped: %w", refused)))
	require.True(t, DeleteDefinitelyRefused(&DeleteNotAttempted{Err: errors.New("breaker open")}))
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, errors.New("socket closed"), &DeleteObjectError{Code: "RequestTimeout"}, &DeleteObjectError{Code: "InternalError"}, &DeleteOutcomeUnknown{Err: refused}} {
		require.False(t, DeleteDefinitelyRefused(err), "%v", err)
	}
}
