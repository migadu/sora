package config

import (
	"testing"
	"time"
)

func TestSieveConfig_GetMaxExecutionTime(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 2 * time.Second},      // default
		{"5s", 5 * time.Second},    // explicit
		{"bogus", 2 * time.Second}, // invalid -> default
		{"0s", 2 * time.Second},    // non-positive -> default
	}
	for _, c := range cases {
		s := &SieveConfig{MaxExecutionTime: c.in}
		if got := s.GetMaxExecutionTime(); got != c.want {
			t.Errorf("GetMaxExecutionTime(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
