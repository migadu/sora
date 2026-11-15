package sieveengine

import (
	"strconv"
	"testing"
)

// TestValidateScript pins what every script write path checks before storing.
func TestValidateScript(t *testing.T) {
	if err := ValidateScript(`require ["fileinto", "mime"]; if header :mime :anychild :type "Content-Type" "image" { fileinto "Images"; }`, nil); err != nil {
		t.Fatalf("default set rejects a script delivery compiles: %v", err)
	}
	if err := ValidateScript(`require "enclose"; keep;`, nil); err == nil {
		t.Fatal("accepted an extension the engine does not have; delivery would skip the script whole")
	}
	if err := ValidateScript(`require "editheader"; addheader "X-A" "b";`, nil); err == nil {
		t.Fatal("accepted editheader, which is opt-in")
	}
	if err := ValidateScript(`require "editheader"; addheader "X-A" "b";`, []string{"editheader"}); err != nil {
		t.Fatalf("rejected editheader although configured: %v", err)
	}
	if err := ValidateScript(`if header :contains "subject" "x" { fileinto "X"; }`, nil); err == nil {
		t.Fatal("accepted fileinto without its require")
	}
}

// RFC 5228 sections 1.1, 2.4.2 and 8.1 require Sieve scripts to be valid UTF-8 and
// forbid NUL octets (0x00) everywhere, including inside comments, quoted strings and
// text: multiline blocks where go-sieve's lexer does not inspect individual bytes.
func TestValidateScriptRefusesNULAndInvalidUTF8(t *testing.T) {
	if err := ValidateScript("# Café ☕\nrequire \"fileinto\";\nfileinto \"Café\";\n", nil); err != nil {
		t.Fatalf("valid UTF-8 script rejected: %v", err)
	}

	for _, tc := range []struct {
		name   string
		script string
	}{
		{"NUL in hash comment", "# \x00\nkeep;\n"},
		{"NUL in bracket comment", "/* \x00 */\nkeep;\n"},
		{"NUL in quoted string", "require \"fileinto\";\nfileinto \"INBOX\x00\";\n"},
		{"escaped NUL in quoted string", "require \"fileinto\";\nfileinto \"INBOX\\\x00\";\n"},
		{"NUL in text multiline block", "require \"vacation\";\nvacation text:\nhello \x00 world\n.\n;\n"},
		{"NUL in text header comment", "require \"vacation\";\nvacation text: # \x00\nhello\n.\n;\n"},
		{"invalid UTF-8 in hash comment", "# \xff\nkeep;\n"},
		{"truncated UTF-8 in hash comment", "# caf\xc3\nkeep;\n"},
		{"invalid UTF-8 in bracket comment", "/* \xff */\nkeep;\n"},
		{"invalid UTF-8 in quoted string", "require \"fileinto\";\nfileinto \"INBOX\xff\";\n"},
		{"invalid UTF-8 in text multiline block", "require \"vacation\";\nvacation text:\nhello \xff world\n.\n;\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateScript(tc.script, nil); err == nil {
				t.Errorf("ValidateScript(%s) = nil, want validation error", strconv.QuoteToASCII(tc.script))
			}
			if _, err := CompileScript(tc.script, EffectiveExtensions(nil)); err == nil {
				t.Errorf("CompileScript(%s) = nil, want validation error", strconv.QuoteToASCII(tc.script))
			}
		})
	}
}
