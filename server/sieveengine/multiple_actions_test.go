package sieveengine

import (
	"context"
	"fmt"
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
		{
			// The second fileinto asked for the mailbox to be created (RFC 5490 §3.2).
			name:   "one mailbox named twice is created if either asks",
			result: Result{Action: ActionFileInto, Mailboxes: []string{"archive", "Archive"}, CreateMailboxes: []string{"Archive"}},
			want:   []Destination{{Mailbox: "archive", Create: true}},
		},
		{
			// Issue #457: "the name created is without the trailing hierarchy
			// delimiter" (RFC 3501 §6.3.3), and the copy goes where it is created.
			name:   "fileinto :create with a trailing delimiter",
			result: Result{Action: ActionFileInto, Mailboxes: []string{"Foo/"}, CreateMailboxes: []string{"Foo/"}},
			want:   []Destination{{Mailbox: "Foo", Create: true}},
		},
		{
			name:   "fileinto :create of Foo/ and fileinto foo are one mailbox",
			result: Result{Action: ActionFileInto, Mailboxes: []string{"Foo/", "foo"}, CreateMailboxes: []string{"Foo/"}},
			want:   []Destination{{Mailbox: "Foo", Create: true}},
		},
		{
			// A name that makes no mailbox is left as it is: creating it fails, and
			// delivery keeps the message.
			name:   "fileinto :create of a name with an empty level",
			result: Result{Action: ActionFileInto, Mailboxes: []string{"x//y"}, CreateMailboxes: []string{"x//y"}},
			want:   []Destination{{Mailbox: "x//y", Create: true}},
		},
		{
			// Without :create the name is looked up as given.
			name:   "fileinto with a trailing delimiter",
			result: Result{Action: ActionFileInto, Mailboxes: []string{"Foo/"}},
			want:   []Destination{{Mailbox: "Foo/"}},
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

// TestTooManyFileintoTargetsIsAnError: every fileinto target is a stored copy, so
// the number of them is bounded (RFC 5228 §2.10.4). A script over the bound is in
// error and none of its actions are carried out: the message is kept, and its
// redirect is neither relayed nor charged.
func TestTooManyFileintoTargetsIsAnError(t *testing.T) {
	script := func(targets int) string {
		s := "require \"fileinto\";\nredirect \"other@example.org\";\n"
		for i := range targets {
			s += fmt.Sprintf("fileinto \"Folder%d\";\n", i)
		}
		return s
	}
	evaluate := func(targets int) (Result, *configurableRedirectOracle, error) {
		ro := &configurableRedirectOracle{}
		result, err := evalRedirectScript(t, script(targets), ro, 100)
		return result, ro, err
	}

	result, ro, err := evaluate(MaxFileintoTargets)
	if err != nil {
		t.Fatalf("%d targets: %v", MaxFileintoTargets, err)
	}
	relayAll(t, result)
	if len(result.Mailboxes) != MaxFileintoTargets || ro.recordedN != 1 {
		t.Errorf("%d targets: filed into %d, charged %d redirects, want %d and 1", MaxFileintoTargets, len(result.Mailboxes), ro.recordedN, MaxFileintoTargets)
	}

	result, ro, err = evaluate(MaxFileintoTargets + 1)
	if err == nil {
		t.Fatalf("%d targets: no error, result %s into %d mailboxes", MaxFileintoTargets+1, result.Action, len(result.Mailboxes))
	}
	if result.Action != ActionKeep || len(result.Mailboxes) != 0 || len(result.RedirectTo) != 0 {
		t.Errorf("%d targets: result %+v, want a plain keep", MaxFileintoTargets+1, result)
	}
	if ro.recordedN != 0 {
		t.Errorf("%d targets: %d redirects charged, want none", MaxFileintoTargets+1, ro.recordedN)
	}
}
