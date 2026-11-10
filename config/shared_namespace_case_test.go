package config

import "testing"

func TestSharedNamespaceMatchesMailboxCaseRules(t *testing.T) {
	for _, tc := range []struct {
		prefix, name string
		want         bool
	}{
		{"Shared/", "shared/team", true},
		{"Shared/", "SHARED", true},
		{"#Team/", "#tEaM/Updates", true},
		{"Public/Rooms/", "PUBLIC/rooms/Team", true},
		{"Public/Rooms/", "public/ROOMS", true},
		{"Shared/", "SharedElsewhere/Team", false},
		{"Public/Rooms/", "Public/Room/Team", false},
	} {
		cfg := SharedMailboxesConfig{Enabled: true, NamespacePrefix: tc.prefix}
		if got := cfg.InNamespace(tc.name); got != tc.want {
			t.Errorf("%q in %q = %v, want %v", tc.name, tc.prefix, got, tc.want)
		}
	}
}
