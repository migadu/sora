package config

import "testing"

// max_script_size "0" is the 16 KiB default, like an omitted value, and not "no
// limit": the ManageSieve server applies GetMaxScriptSize at start-up and on every
// reload, so the two cannot disagree (#336).
func TestGetMaxScriptSizeZeroIsDefault(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want int64
	}{
		{"", 16 * 1024},
		{"0", 16 * 1024},
		{"0kb", 16 * 1024},
		{"0 MB", 16 * 1024},
		{"1", 1},
		{"64kb", 64 * 1024},
	} {
		s := ServerConfig{Name: "sieve", Type: "managesieve", MaxScriptSize: tt.in}
		if got, err := s.GetMaxScriptSize(); err != nil || got != tt.want {
			t.Errorf("GetMaxScriptSize(%q) = %d, %v; want %d, nil", tt.in, got, err, tt.want)
		}
		if got := s.GetMaxScriptSizeWithDefault(); got != tt.want {
			t.Errorf("GetMaxScriptSizeWithDefault(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
	s := ServerConfig{Name: "sieve", Type: "managesieve", MaxScriptSize: "32 kilobytes"}
	if _, err := s.GetMaxScriptSize(); err == nil {
		t.Error("GetMaxScriptSize(\"32 kilobytes\") = nil error, want a parse error")
	}
}
