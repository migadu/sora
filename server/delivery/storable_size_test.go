package delivery

import (
	"errors"
	"math"
	"testing"
)

// max_message_size is capped at the largest message sora can store, but LMTP and the
// Admin API store more than they read: the Received and Delivered-To trace headers and
// any Sieve header edits. A message read at the cap therefore reached the database
// insert above 2,147,483,647 octets and failed there, which LMTP answered with a 4xx
// the sender retries (#555). CheckStorableSize, run on the final bytes before they are
// staged, refuses it as too large instead.
func TestCheckStorableSize(t *testing.T) {
	tests := []struct {
		size    int
		tooBig  bool
		comment string
	}{
		{math.MaxInt32 + 1, true, "one octet above the storable maximum"},
		{math.MaxInt32 + 300, true, "a message read at the cap plus its trace headers"},
		{math.MaxInt32, false, "the storable maximum itself"},
		{50 << 20, false, "an ordinary message"},
	}
	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			err := CheckStorableSize(tt.size)
			if got := errors.Is(err, ErrMessageTooLarge); got != tt.tooBig {
				t.Errorf("CheckStorableSize(%d) = %v, want ErrMessageTooLarge %v", tt.size, err, tt.tooBig)
			}
			if !tt.tooBig && err != nil {
				t.Errorf("CheckStorableSize(%d) = %v, want nil", tt.size, err)
			}
		})
	}
}
