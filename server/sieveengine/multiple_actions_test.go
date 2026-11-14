package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestEveryFileintoAndRedirectIsReported is issue #322: the result must carry
// every fileinto target and every redirect a script ran. Only the first target
// used to be reported, and a redirect next to a fileinto not at all.
func TestEveryFileintoAndRedirectIsReported(t *testing.T) {
	tests := []struct {
		name          string
		script        string
		wantMailboxes []string
		wantRedirect  []string
		wantKeep      bool // Copy: INBOX gets a copy too
	}{
		{
			name:          "fileinto then redirect",
			script:        "require \"fileinto\";\nfileinto \"Archive\";\nredirect \"other@example.org\";\n",
			wantMailboxes: []string{"Archive"},
			wantRedirect:  []string{"other@example.org"},
		},
		{
			name:          "redirect then fileinto",
			script:        "require \"fileinto\";\nredirect \"other@example.org\";\nfileinto \"Archive\";\n",
			wantMailboxes: []string{"Archive"},
			wantRedirect:  []string{"other@example.org"},
		},
		{
			name:          "fileinto :copy and redirect :copy",
			script:        "require [\"fileinto\", \"copy\"];\nfileinto :copy \"Archive\";\nredirect :copy \"other@example.org\";\n",
			wantMailboxes: []string{"Archive"},
			wantRedirect:  []string{"other@example.org"},
			wantKeep:      true,
		},
		{
			name:          "fileinto twice",
			script:        "require \"fileinto\";\nfileinto \"Archive\";\nfileinto \"Projects\";\n",
			wantMailboxes: []string{"Archive", "Projects"},
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
			if !slices.Equal(result.Mailboxes, tt.wantMailboxes) {
				t.Errorf("Mailboxes = %v, want %v", result.Mailboxes, tt.wantMailboxes)
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

// TestResultDestinations: the message is stored in every fileinto target and in
// INBOX when it is kept, each mailbox once; a failed redirect keeps a message that
// would otherwise be stored nowhere.
func TestResultDestinations(t *testing.T) {
	inbox := Destination{Mailbox: "INBOX"}
	tests := []struct {
		name           string
		result         Result
		redirectFailed bool
		want           []Destination
	}{
		{name: "keep", result: Result{Action: ActionKeep}, want: []Destination{inbox}},
		{name: "discard", result: Result{Action: ActionDiscard}},
		{name: "fileinto", result: Result{Action: ActionFileInto, Mailboxes: []string{"Archive"}}, want: []Destination{{Mailbox: "Archive"}}},
		{
			name:   "fileinto twice and keep",
			result: Result{Action: ActionFileInto, Mailboxes: []string{"Archive", "Projects"}, Copy: true},
			want:   []Destination{{Mailbox: "Archive"}, {Mailbox: "Projects"}, inbox},
		},
		{
			name:   "fileinto :create",
			result: Result{Action: ActionFileInto, Mailboxes: []string{"Archive", "New"}, CreateMailboxes: []string{"New"}},
			want:   []Destination{{Mailbox: "Archive"}, {Mailbox: "New", Create: true}},
		},
		{
			name:   "names differing in case are one mailbox",
			result: Result{Action: ActionFileInto, Mailboxes: []string{"inbox", "Archive", "archive"}, Copy: true},
			want:   []Destination{{Mailbox: "inbox"}, {Mailbox: "Archive"}},
		},
		{name: "redirect", result: Result{Action: ActionRedirect, RedirectTo: []string{"a@example.org"}}},
		{
			name:   "redirect :copy",
			result: Result{Action: ActionRedirect, RedirectTo: []string{"a@example.org"}, Copy: true},
			want:   []Destination{inbox},
		},
		{
			name:           "failed redirect is kept",
			result:         Result{Action: ActionRedirect, RedirectTo: []string{"a@example.org"}},
			redirectFailed: true,
			want:           []Destination{inbox},
		},
		{
			name:           "failed redirect next to fileinto",
			result:         Result{Action: ActionFileInto, Mailboxes: []string{"Archive"}, RedirectTo: []string{"a@example.org"}},
			redirectFailed: true,
			want:           []Destination{{Mailbox: "Archive"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.Destinations(tt.redirectFailed); !slices.Equal(got, tt.want) {
				t.Errorf("Destinations(%v) = %v, want %v", tt.redirectFailed, got, tt.want)
			}
		})
	}
}
