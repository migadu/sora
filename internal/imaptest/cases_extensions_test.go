package imaptest

import (
	"errors"
	"slices"
	"testing"
)

func TestExtensionUIDSets(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []uint64
	}{
		{"739", []uint64{739}},
		{"102:104,8", []uint64{8, 102, 103, 104}},
		{"104:102,103", []uint64{102, 103, 104}},
		{"4294967295", []uint64{4294967295}},
	} {
		t.Run(tc.text, func(t *testing.T) {
			got, err := extUIDSet(tc.text)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("UID set %q: got %v, %v; want %v", tc.text, got, err, tc.want)
			}
		})
	}
	for _, text := range []string{"", "0", "1:*", "1:2:3", "-1", "4294967296", "1:4294967295", "5,"} {
		t.Run("invalid/"+text, func(t *testing.T) {
			_, err := extUIDSet(text)
			var assertion *AssertionError
			if !errors.As(err, &assertion) {
				t.Fatalf("untrusted UID set %q did not produce an assertion error: %v", text, err)
			}
		})
	}
}

func TestReselectedUIDValidity(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		beforeUID, afterUID           uint64
		beforeValidity, afterValidity uint64
		wantFailure                   bool
	}{
		{name: "persistent", beforeUID: 37, afterUID: 37, beforeValidity: 100, afterValidity: 100},
		{name: "legal-regeneration", beforeUID: 37, afterUID: 2, beforeValidity: 100, afterValidity: 101},
		{name: "generation-with-same-uid", beforeUID: 37, afterUID: 37, beforeValidity: 100, afterValidity: 101},
		{name: "changed-uid-with-same-validity", beforeUID: 37, afterUID: 2, beforeValidity: 100, afterValidity: 100, wantFailure: true},
		{name: "regeneration-with-older-validity", beforeUID: 37, afterUID: 2, beforeValidity: 100, afterValidity: 99, wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := extCheckReselectedUID(tc.beforeUID, tc.afterUID, tc.beforeValidity, tc.afterValidity)
			if (err != nil) != tc.wantFailure {
				t.Fatalf("reselect check error=%v, want failure=%t", err, tc.wantFailure)
			}
		})
	}
}
