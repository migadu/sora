package main

import (
	"math"
	"testing"
)

// The import refuses a message above the largest one sora can store, whatever its
// limit says: messages.size and pending_uploads.size are INTEGER columns, so a
// message above 2,147,483,647 octets was read into memory and uploaded, then failed
// at the database insert (#555). The limit comes from admin_cli.import_message_limit
// or the IMAP server's append_limit, neither of which has that ceiling, and a limit
// of 0 checked nothing at all.
func TestValidateMessageRefusesUnstorableSize(t *testing.T) {
	const gib = int64(1) << 30
	tests := []struct {
		name    string
		limit   int64
		size    int64
		wantErr bool
	}{
		{"above storable under a 3gb limit", 3 * gib, math.MaxInt32 + 1, true},
		{"above storable under a 4gb limit", 4 * gib, 3 * gib, true},
		{"above storable without a limit", 0, math.MaxInt32 + 1, true},
		{"largest storable under a 3gb limit", 3 * gib, math.MaxInt32, false},
		{"largest storable without a limit", 0, math.MaxInt32, false},
		{"above the configured limit", 1024, 2048, true},
		{"within the configured limit", 1024, 1024, false},
		{"empty", 1024, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &Importer{options: ImporterOptions{MaxMessageSize: tt.limit}}
			err := i.validateMessage(tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMessage(%d) with limit %d = %v, want error %v", tt.size, tt.limit, err, tt.wantErr)
			}
		})
	}
}
