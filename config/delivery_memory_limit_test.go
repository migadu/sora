package config

import (
	"strings"
	"testing"
)

func TestDeliveryMemoryLimit(t *testing.T) {
	for _, tc := range []struct {
		name, limit string
		want        int64
		warns       bool
	}{
		{"unset is no limit", "", 0, false},
		{"zero is no limit", "0", 0, false},
		{"at max_message_size", "50mb", 50 * 1024 * 1024, false},
		{"below max_message_size", "10mb", 10 * 1024 * 1024, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := ServerConfig{Name: "lmtp1", Type: "lmtp", Limits: &ServerLimitsConfig{DeliveryMemoryLimit: tc.limit}}
			got, err := s.GetDeliveryMemoryLimit()
			if err != nil || got != tc.want {
				t.Fatalf("GetDeliveryMemoryLimit() = %d, %v; want %d", got, err, tc.want)
			}
			var warnings []string
			s.WarnDeliveryMemoryLimit(func(format string, args ...any) { warnings = append(warnings, format) })
			if (len(warnings) > 0) != tc.warns {
				t.Fatalf("warnings %q, want a warning: %v", warnings, tc.warns)
			}
			if tc.warns && !strings.Contains(warnings[0], "delivery_memory_limit") {
				t.Fatalf("warning does not name the key: %q", warnings[0])
			}
		})
	}
	bad := ServerConfig{Limits: &ServerLimitsConfig{DeliveryMemoryLimit: "lots"}}
	if _, err := bad.GetDeliveryMemoryLimit(); err == nil {
		t.Fatal("an unparsable delivery_memory_limit was accepted")
	}
}
