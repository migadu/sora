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

func TestSharedNamespaceRootMatchesMailboxCaseRules(t *testing.T) {
	for _, tc := range []struct {
		prefix, name string
		enabled      bool
		want         bool
	}{
		{"Shared/", "Shared", true, true},
		{"Shared/", "sHARED", true, true},
		{"Public/Rooms/", "public/ROOMS", true, true},
		{"Shared/", "Shared", false, false},
		{"Shared/", "Shared/Team", true, false},
		{"Shared/", "Shared/", true, false},
		{"Shared/", "SharedDocs", true, false},
		{"Public/Rooms/", "Public", true, false},
		{"Shared/", "", true, false},
	} {
		cfg := SharedMailboxesConfig{Enabled: tc.enabled, NamespacePrefix: tc.prefix}
		got := cfg.IsNamespaceRoot(tc.name)
		if got != tc.want {
			t.Errorf("%q is the root of %q (enabled=%v) = %v, want %v", tc.name, tc.prefix, tc.enabled, got, tc.want)
		}
		if got && !cfg.InNamespace(tc.name) {
			t.Errorf("%q is the root of %q but not in its namespace", tc.name, tc.prefix)
		}
	}
}
