package helpers

import "testing"

func TestParseSizeUnitsCaseInsensitive(t *testing.T) {
	const (
		kib = int64(1024)
		mib = 1024 * kib
		gib = 1024 * mib
		tib = 1024 * gib
	)
	tests := []struct {
		in   string
		want int64
	}{
		{"2048", 2048},
		{"2048b", 2048},
		{"2048B", 2048},
		{"16kb", 16 * kib},
		{"16KB", 16 * kib},
		{"16Kb", 16 * kib},
		{"16kB", 16 * kib},
		{"25mb", 25 * mib},
		{"25MB", 25 * mib},
		{"25 MB", 25 * mib},
		{"1gb", gib},
		{"1GB", gib},
		{"100GB", 100 * gib},
		{"1tb", tib},
		{"1TB", tib},
	}
	for _, tt := range tests {
		got, err := ParseSize(tt.in)
		if err != nil {
			t.Errorf("ParseSize(%q) error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseSizeRejectsInvalid(t *testing.T) {
	for _, in := range []string{"", "mb", "-5mb", "5 xb", "5pb", "1.5gb", "9223372036854775807kb", "8388608tb"} {
		if got, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) = %d, want error", in, got)
		}
	}
}
