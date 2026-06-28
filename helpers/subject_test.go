package helpers

import "testing"

func TestNormalizeSubjectForSort(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// Basic cases.
		{"empty", "", ""},
		{"plain", "Hello World", "HELLO WORLD"},
		{"trim and collapse whitespace", "  Hello   World  ", "HELLO WORLD"},
		{"tabs collapsed", "Hello\tWorld", "HELLO WORLD"},

		// subj-refwd: reply.
		{"re", "Re: Hello", "HELLO"},
		{"re upper", "RE: Hello", "HELLO"},
		{"re lower", "re: hello", "HELLO"},
		{"re no space", "Re:Hello", "HELLO"},
		{"re extra space", "Re:    Hello", "HELLO"},
		{"nested re", "Re: Re: Hello", "HELLO"},
		{"re with blob counter", "Re[2]: Hello", "HELLO"},
		// RFC 5256 subj-blob is bracketed only; a parenthesized "Re(3):" counter
		// is not a valid refwd and is left intact.
		{"re with paren counter not stripped", "Re(3): Hello", "RE(3): HELLO"},

		// subj-refwd: forward (only fw / fwd per RFC 5256).
		{"fwd", "Fwd: Hello", "HELLO"},
		{"fw", "FW: Hello", "HELLO"},
		{"fwd lower", "fwd: hello", "HELLO"},
		{"mixed re and fwd", "Fwd: Re: Hello", "HELLO"},

		// "Forward:" and "Reply:" are NOT in the RFC 5256 grammar; left intact.
		{"forward word not stripped", "Forward: Hello", "FORWARD: HELLO"},
		{"reply word not stripped", "Reply: Hello", "REPLY: HELLO"},
		{"aw not stripped", "AW: Hello", "AW: HELLO"},

		// subj-blob (mailing-list tags) in leading position.
		{"leading blob", "[list] Hello", "HELLO"},
		{"blob then refwd", "[list] Re: Hello", "HELLO"},
		{"refwd then blob", "Re: [list] Hello", "HELLO"},
		{"multiple leading blobs", "[a][b] Hello", "HELLO"},
		{"blob only stays", "[list]", "[LIST]"},
		{"blob only with space stays", "[list] ", "[LIST]"},

		// subj-trailer.
		{"trailing fwd", "Hello (fwd)", "HELLO"},
		{"trailing fwd doubled", "Hello (fwd) (fwd)", "HELLO"},
		{"trailing fwd upper", "Hello (FWD)", "HELLO"},

		// subj-fwd wrapper (step 6).
		{"fwd wrapper", "[fwd: Hello]", "HELLO"},
		{"fwd wrapper with re inside", "[fwd: Re: Hello]", "HELLO"},
		{"fwd wrapper nested", "[fwd: [fwd: Hello]]", "HELLO"},

		// Combinations.
		{"everything", "Fwd: Re: [tag] Hello (fwd)", "HELLO"},
		{"blob refwd blob", "[a] Re: [b] Hello", "HELLO"},

		// Degenerate inputs that reduce to empty base.
		{"refwd only", "Re:", ""},
		{"fwd only", "FWD:", ""},
		{"trailer only", "(fwd)", ""},

		// Non-ASCII content is preserved (only the base subject is extracted).
		{"unicode body", "Re: Grüße", "GRÜßE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeSubjectForSort(tt.in); got != tt.want {
				t.Errorf("NormalizeSubjectForSort(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeSubjectForSortIdempotent verifies that applying the algorithm to
// its own output is a no-op (the base subject of a base subject is itself).
func TestNormalizeSubjectForSortIdempotent(t *testing.T) {
	inputs := []string{
		"Re: Re: [list] Hello (fwd)",
		"[fwd: Re: Hello]",
		"Fwd: [a][b] Project update",
		"plain subject",
		"[list]",
		"",
	}
	for _, in := range inputs {
		once := NormalizeSubjectForSort(in)
		twice := NormalizeSubjectForSort(once)
		if once != twice {
			t.Errorf("not idempotent for %q: once=%q twice=%q", in, once, twice)
		}
	}
}

// TestBaseSubjectGroupsThreadVariants verifies that the variants of a subject
// that RFC 5256 considers part of the same thread collapse to one base subject.
func TestBaseSubjectGroupsThreadVariants(t *testing.T) {
	base := NormalizeSubjectForSort("Project kickoff")
	variants := []string{
		"Re: Project kickoff",
		"RE: RE: Project kickoff",
		"Fwd: Project kickoff",
		"[team] Re: Project kickoff",
		"Re: [team] Project kickoff (fwd)",
	}
	for _, v := range variants {
		if got := NormalizeSubjectForSort(v); got != base {
			t.Errorf("variant %q normalized to %q, want %q (same thread as base)", v, got, base)
		}
	}
}
