package main

import (
	"slices"
	"strings"
	"testing"
)

// TestClosingRefs: GitHub closes what a closing keyword names when the pull request (or a
// commit) carrying it merges into the default branch, pull requests and other
// repositories included. Only a keyword in front of this repository's issues may pass.
func TestClosingRefs(t *testing.T) {
	const repo = "migadu/sora"
	for _, tc := range []struct {
		name string
		text string
		want []string
	}{
		// The forms that closed go-imap pull requests unmerged.
		{"colon form from a merged description",
			"Fix: migadu/go-imap#227 gives CHECK its own handler.",
			[]string{"Fix: migadu/go-imap#227"}},
		{"plain keyword", "Fixes migadu/go-imap#228", []string{"Fixes migadu/go-imap#228"}},
		{"upper case", "CLOSES: migadu/go-sieve#6", []string{"CLOSES: migadu/go-sieve#6"}},
		{"past tense", "resolved migadu/go-smtp#17.", []string{"resolved migadu/go-smtp#17"}},
		{"pull request URL in another repository",
			"Closes https://github.com/migadu/go-imap/pull/231",
			[]string{"Closes https://github.com/migadu/go-imap/pull/231"}},
		{"issue URL in another repository",
			"fixes https://github.com/migadu/go-pop3/issues/3",
			[]string{"fixes https://github.com/migadu/go-pop3/issues/3"}},
		{"markdown link", "Fix [migadu/go-imap#230](https://github.com/migadu/go-imap/pull/230)",
			[]string{"Fix [migadu/go-imap#230"}},
		{"line break after the keyword", "the fix:\nmigadu/go-imap#227", []string{"fix:\nmigadu/go-imap#227"}},
		{"second keyword in a list", "Fixes #1646, fixes migadu/go-imap#227.",
			[]string{"fixes migadu/go-imap#227"}},
		{"pull request URL in this repository", "Closes https://github.com/migadu/sora/pull/1505",
			[]string{"Closes https://github.com/migadu/sora/pull/1505"}},
		{"several findings", "Fix: migadu/go-imap#216.\n\nFix: migadu/go-imap#219.",
			[]string{"Fix: migadu/go-imap#216", "Fix: migadu/go-imap#219"}},

		// What a Sora pull request should write.
		{"this repository's issue", "Fixes #1646.", nil},
		{"this repository by name", "Fixes migadu/sora#1646", nil},
		{"this repository by name, other case", "Fixes Migadu/Sora#1646", nil},
		{"this repository's issue URL", "Closes https://github.com/migadu/sora/issues/1646", nil},
		{"neutral dependency", "Depends on migadu/go-imap#227", nil},
		{"neutral upstream note", "Upstream dependency: migadu/go-imap#227", nil},
		// Only the reference right after a keyword is closed.
		{"second reference without its own keyword", "Fixes #1646 and migadu/go-imap#227", nil},
		// From a merged description: a keyword, but no reference after it.
		{"keyword not followed by a reference",
			"Fix: go-imap branch `pin/1382-enable-requires-capability` (`9a034e5`) merges #231.", nil},
		// From a merged commit: the subject ends with the keyword, the body starts with
		// the reference.
		{"blank line after the keyword",
			"lmtp: re-pin go-smtp #25 with its LMTP BDAT LAST rows fixed\n\nmigadu/go-smtp#25's test expected 503", nil},
		{"keyword inside a word", "the prefix migadu/go-imap#227", nil},
		{"other inflection", "fixing migadu/go-imap#227", nil},
		{"code span around the keyword", "write `Fix:` before a `migadu/go-imap#N` reference", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := closingRefs(tc.text, repo); !slices.Equal(got, tc.want) {
				t.Errorf("closingRefs(%q) = %q, want %q", tc.text, got, tc.want)
			}
		})
	}
}

// TestRunFailsOnAForeignClosingRef: the workflow relies on the exit status, and the
// output has to say what to write instead.
func TestRunFailsOnAForeignClosingRef(t *testing.T) {
	var out strings.Builder
	if code := run(strings.NewReader("Fixes #1646.\n\nFix: migadu/go-imap#227 adds a handler.\n"), &out, "migadu/sora"); code != 1 {
		t.Errorf("exit status %d, want 1", code)
	}
	for _, want := range []string{`"Fix: migadu/go-imap#227"`, "Depends on"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if code := run(strings.NewReader("Fixes #1646.\n\nDepends on migadu/go-imap#227.\n"), &out, "migadu/sora"); code != 0 || out.Len() != 0 {
		t.Errorf("exit status %d, output %q; want 0 and no output", code, out.String())
	}
}
