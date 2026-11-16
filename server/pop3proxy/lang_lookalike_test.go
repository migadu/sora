package pop3proxy

import (
	"context"
	"testing"
)

// LANG takes a language range (RFC 6856 section 3, RFC 4647 section 2.1), ASCII letters,
// digits and hyphens compared case-insensitively. strings.ToLower maps U+0130 (LATIN
// CAPITAL LETTER I WITH DOT ABOVE) to "i", so "İ-DEFAULT" was taken for i-default.
func TestSetLanguageMatchesASCIIOnly(t *testing.T) {
	ctx := context.Background()
	s := &POP3ProxySession{}
	if tag, err := s.SetLanguage(ctx, "İ-DEFAULT"); err == nil {
		t.Errorf("SetLanguage(İ-DEFAULT) = %q, want an error", tag)
	}
	for lang, want := range map[string]string{"I-Default": "i-default", "EN": "en", "*": "en"} {
		if tag, err := s.SetLanguage(ctx, lang); err != nil || tag != want {
			t.Errorf("SetLanguage(%s) = %q, %v; want %q", lang, tag, err, want)
		}
	}
}
