package config

import (
	"math"
	"strings"
	"testing"
)

// max_message_size (LMTP, LMTP proxy, Admin API delivery) is clamped to the largest
// message sora can store: messages.size and pending_uploads.size are INTEGER columns,
// so a message above 2,147,483,647 octets passed the size check, was read into memory,
// and then failed at the database insert, while the LMTP proxy advertised a SIZE no
// backend accepts (#555). RFC 1870 section 5: "The fixed maximum message size is
// defined as the message size of the largest message that a server is ever willing to
// accept. [...] The fixed maximum message size may be an implementation artifact of
// the SMTP server, or it may be chosen by the administrator of the server."
func TestMaxMessageSizeAboveStorableIsClamped(t *testing.T) {
	tests := []struct {
		configured string
		want       int64
		warns      bool
	}{
		{"3gb", math.MaxInt32, true},
		{"4gb", math.MaxInt32, true},
		{"2gb", math.MaxInt32, true},
		{"2147483648", math.MaxInt32, true},
		{"2147483647", math.MaxInt32, false},
		{"2147483646", math.MaxInt32 - 1, false},
		{"50mb", 50 << 20, false},
		{"", 50 << 20, false},
	}
	for _, tt := range tests {
		t.Run(tt.configured, func(t *testing.T) {
			buf := captureWarnings(t)
			srv := ServerConfig{Name: "lmtp-size", Type: "lmtp", MaxMessageSize: tt.configured}

			if got := srv.GetMaxMessageSizeWithDefault(); got != tt.want {
				t.Errorf("max_message_size %q = %d, want %d", tt.configured, got, tt.want)
			}
			out := buf.String()
			warned := strings.Contains(out, "level=WARN") && strings.Contains(out, "max_message_size") && strings.Contains(out, "lmtp-size")
			if warned != tt.warns {
				t.Errorf("max_message_size %q: warned = %v, want %v; logged %q", tt.configured, warned, tt.warns, out)
			}
		})
	}
}
