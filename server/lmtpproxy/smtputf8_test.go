package lmtpproxy

import "testing"

func TestHasSMTPUTF8Param(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"parameter present", []string{"FROM:<josé@example.com>", "SMTPUTF8"}, true},
		{"parameter is case-insensitive", []string{"FROM:<a@b.c>", "smtputf8"}, true},
		{"among other parameters", []string{"FROM:<a@b.c>", "SIZE=12", "SMTPUTF8", "BODY=8BITMIME"}, true},
		{"other parameters only", []string{"FROM:<a@b.c>", "SIZE=12", "BODY=8BITMIME"}, false},
		{"no parameters", []string{"FROM:<a@b.c>"}, false},
		{"takes no value, so a valued token is not it", []string{"FROM:<a@b.c>", "SMTPUTF8=1"}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasSMTPUTF8Param(tt.args); got != tt.want {
				t.Errorf("hasSMTPUTF8Param(%q) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestIsSMTPUTF8Capability(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"250-SMTPUTF8\r\n", true},
		{"250 SMTPUTF8\r\n", true},
		{"250-smtputf8", true},
		{"250-SIZE 1024", false},
		{"250-PIPELINING", false},
		{"250-SMTPUTF8X", false},
		{"250", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isSMTPUTF8Capability(tt.line); got != tt.want {
			t.Errorf("isSMTPUTF8Capability(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

// The SMTPUTF8 parameter is forwarded to the backend only when the transaction needs it
// AND the backend advertised the extension; a legacy backend gets the plain command.
func TestBackendMailFrom(t *testing.T) {
	tests := []struct {
		name            string
		smtputf8        bool
		backendSMTPUTF8 bool
		want            string
	}{
		{"plain transaction, capable backend", false, true, "MAIL FROM:<josé@example.com>"},
		{"plain transaction, legacy backend", false, false, "MAIL FROM:<josé@example.com>"},
		{"internationalized, capable backend", true, true, "MAIL FROM:<josé@example.com> SMTPUTF8"},
		{"internationalized, legacy backend is downgraded", true, false, "MAIL FROM:<josé@example.com>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{sender: "josé@example.com", smtputf8: tt.smtputf8, backendSMTPUTF8: tt.backendSMTPUTF8}
			if got := s.backendMailFrom(); got != tt.want {
				t.Errorf("backendMailFrom() = %q, want %q", got, tt.want)
			}
		})
	}
}
