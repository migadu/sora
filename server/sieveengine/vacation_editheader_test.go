package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestVacationSubjectSeesHeaderEdits: without :subject the reply's subject is "Auto: "
// and the subject of the message (RFC 5230 §5.3), and RFC 5293 §7 names vacation
// among the actions that "MUST examine the current state of a header as modified
// by any actions that have taken place so far". go-sieve took the Subject the
// message arrived with, so a Subject that deleteheader removed or addheader replaced
// before the vacation action was still quoted in the reply.
func TestVacationSubjectSeesHeaderEdits(t *testing.T) {
	ctx := rawContext(t, "From: a@example.com\r\n"+
		"Subject: hello\r\n"+
		"\r\nbody\r\n")

	// editheader is not in the default [sieve] enabled_extensions.
	extensions := EffectiveExtensions(append(slices.Clone(DefaultSieveExtensions), "editheader"))
	for _, tc := range []struct {
		name   string
		script string
		want   string
	}{
		{name: "original subject", script: `vacation "away";`, want: "Auto: hello"},
		{name: "replaced subject",
			script: `deleteheader "Subject"; addheader "Subject" "[list] hello"; vacation "away";`,
			want:   "Auto: [list] hello"},
		{name: "deleted subject", script: `deleteheader "Subject"; vacation "away";`, want: "Automated reply"},
		// "so far": an edit after the action does not change what it saw.
		{name: "subject deleted after the action", script: `vacation "away"; deleteheader "Subject";`, want: "Auto: hello"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `require ["vacation", "editheader"];
` + tc.script + "\n"
			executor, err := NewSieveExecutorWithExtensions(script, extensions)
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, script)
			}
			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if result.Vacation == nil {
				t.Fatalf("%s: no vacation reply", tc.script)
			}
			if result.Vacation.Subject != tc.want {
				t.Errorf("%s: reply subject = %q, want %q", tc.script, result.Vacation.Subject, tc.want)
			}
		})
	}
}
