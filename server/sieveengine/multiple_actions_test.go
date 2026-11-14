package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestEveryFileintoAndRedirectIsReported is issue #322: the result must carry
// every redirect a script ran, also next to a fileinto, which used to replace it.
func TestEveryFileintoAndRedirectIsReported(t *testing.T) {
	tests := []struct {
		name         string
		script       string
		wantRedirect []string
		wantKeep     bool // Copy: INBOX gets a copy too
	}{
		{
			name:         "fileinto then redirect",
			script:       "require \"fileinto\";\nfileinto \"Archive\";\nredirect \"other@example.org\";\n",
			wantRedirect: []string{"other@example.org"},
		},
		{
			name:         "redirect then fileinto",
			script:       "require \"fileinto\";\nredirect \"other@example.org\";\nfileinto \"Archive\";\n",
			wantRedirect: []string{"other@example.org"},
		},
		{
			name:         "fileinto :copy and redirect :copy",
			script:       "require [\"fileinto\", \"copy\"];\nfileinto :copy \"Archive\";\nredirect :copy \"other@example.org\";\n",
			wantRedirect: []string{"other@example.org"},
			wantKeep:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(tt.script, []string{"fileinto", "copy"})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "user@example.com",
				Header:       map[string][]string{"Subject": {"Test"}, "From": {"sender@example.com"}},
				Message:      bodyOnly("body"),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if result.Action != ActionFileInto {
				t.Errorf("action = %s, want %s", result.Action, ActionFileInto)
			}
			if !slices.Equal(result.RedirectTo, tt.wantRedirect) {
				t.Errorf("RedirectTo = %v, want %v", result.RedirectTo, tt.wantRedirect)
			}
			if result.Copy != tt.wantKeep {
				t.Errorf("Copy = %v, want %v", result.Copy, tt.wantKeep)
			}
		})
	}
}
