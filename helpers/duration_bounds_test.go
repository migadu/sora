package helpers

import (
	"testing"
	"time"
)

func TestParseDurationDaysRejectsOverflowAndRepeatedSigns(t *testing.T) {
	for _, value := range []string{"2305843009213693952d", "-2305843009213693952d", "106752d", "-106752d", "--1d", "+-1d", "++1d", "-+1d"} {
		if d, err := ParseDuration(value); err == nil {
			t.Errorf("ParseDuration(%q)=%v, want error", value, d)
		}
	}
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{{"106751d", 106751 * 24 * time.Hour}, {"-106751d", -106751 * 24 * time.Hour}, {"+1d", 24 * time.Hour}} {
		if d, err := ParseDuration(tc.value); err != nil || d != tc.want {
			t.Errorf("ParseDuration(%q)=%v,%v; want %v", tc.value, d, err, tc.want)
		}
	}
}
