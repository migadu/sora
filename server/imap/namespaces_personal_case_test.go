package imap

import (
	"testing"

	"github.com/migadu/sora/config"
)

func TestPersonalNamespaceMatchesCreationCaseRules(t *testing.T) {
	for _, tc := range []struct {
		root, name string
		shared     bool
	}{
		{"Shared", "shared", true},
		{"Shared", "shared/Child", true},
		{"Shared", "shared/", true},
		{"Shared", "SharedDocs", false},
		{"Shared", "ſhared", false},
		{"Shared", "ſhared/Child", false},
		{"ΑΣ", "ασ", true},
		{"ΑΣ", "ασ/Child", true},
		{"ΑΣ", "ας", false},
		{"ΑΣ", "ας/Child", false},
		{"İx", "ix", true},
		{"İx", "ix/Child", true},
		{"Public/Teams", "PUBLIC/teams/Child", true},
		{"Public/Teams", "Public/Teamship", false},
	} {
		t.Run(tc.root+"/"+tc.name, func(t *testing.T) {
			cfg := config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: tc.root + "/"}
			if got := cfg.InNamespace(tc.name); got != tc.shared {
				t.Fatalf("creation fixture = %v, want %v", got, tc.shared)
			}
			if got := inSharedNamespace(tc.name, tc.root); got != tc.shared {
				t.Errorf("shared classification = %v, want %v", got, tc.shared)
			}
		})
	}
	if inSharedNamespace("Shared/Child", "") {
		t.Error("sharing disabled: personal name classified as shared")
	}
}
