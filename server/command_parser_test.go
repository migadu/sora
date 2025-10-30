package server

import (
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		hasTag   bool
		wantTag  string
		wantCmd  string
		wantArgs []string
		wantErr  bool
	}{
		{
			name:     "empty line",
			line:     "",
			hasTag:   true,
			wantTag:  "",
			wantCmd:  "",
			wantArgs: nil,
			wantErr:  false,
		},
		{
			name:     "tag only",
			line:     "A001",
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "",
			wantArgs: nil,
			wantErr:  false,
		},
		{
			name:     "tag and command",
			line:     "A001 NOOP",
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "NOOP",
			wantArgs: nil,
			wantErr:  false,
		},
		{
			name:     "simple LOGIN with atoms",
			line:     "A001 LOGIN user password",
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{"user", "password"},
			wantErr:  false,
		},
		{
			name:     "LOGIN with quoted email",
			line:     `A001 LOGIN "user@example.com" password`,
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{`"user@example.com"`, "password"},
			wantErr:  false,
		},
		{
			name:     "LOGIN with quoted password",
			line:     `A001 LOGIN user@example.com "password"`,
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{"user@example.com", `"password"`},
			wantErr:  false,
		},
		{
			name:     "LOGIN with both quoted",
			line:     `A001 LOGIN "user@example.com" "password"`,
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{`"user@example.com"`, `"password"`},
			wantErr:  false,
		},
		{
			name:     "password with backslash (escaped)",
			line:     `A001 LOGIN "user@example.com" "foo\\bar"`,
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{`"user@example.com"`, `"foo\\bar"`},
			wantErr:  false,
		},
		{
			name:     "password with escaped quote",
			line:     `A001 LOGIN "user@example.com" "foo\"bar"`,
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{`"user@example.com"`, `"foo\"bar"`},
			wantErr:  false,
		},
		{
			name:     "password with backslash before quote (escaped)",
			line:     `A001 LOGIN "user@example.com" "foo\\\"bar"`,
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{`"user@example.com"`, `"foo\\\"bar"`},
			wantErr:  false,
		},
		{
			name:     "complex password with multiple escapes",
			line:     `A001 LOGIN "user@example.com" "pass\\word\"with\\\"escapes"`,
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{`"user@example.com"`, `"pass\\word\"with\\\"escapes"`},
			wantErr:  false,
		},
		{
			name:     "unclosed quote",
			line:     `A001 LOGIN "user@example.com" "password`,
			hasTag:   true,
			wantTag:  "",
			wantCmd:  "",
			wantArgs: nil,
			wantErr:  true,
		},
		{
			name:     "quote escaped at end of string",
			line:     `A001 LOGIN "user@example.com" "password\\"`,
			hasTag:   true,
			wantTag:  "A001",
			wantCmd:  "LOGIN",
			wantArgs: []string{`"user@example.com"`, `"password\\"`},
			wantErr:  false,
		},
		{
			name:     "ManageSieve authenticate",
			line:     `AUTHENTICATE "PLAIN" "dXNlcgB1c2VyAHBhc3N3b3Jk"`,
			hasTag:   false,
			wantTag:  "",
			wantCmd:  "AUTHENTICATE",
			wantArgs: []string{`"PLAIN"`, `"dXNlcgB1c2VyAHBhc3N3b3Jk"`},
			wantErr:  false,
		},
		{
			name:     "POP3 USER command",
			line:     "USER testuser@example.com",
			hasTag:   false,
			wantTag:  "",
			wantCmd:  "USER",
			wantArgs: []string{"testuser@example.com"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, cmd, args, err := ParseLine(tt.line, tt.hasTag)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseLine() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseLine() unexpected error: %v", err)
				return
			}

			if tag != tt.wantTag {
				t.Errorf("ParseLine() tag = %q, want %q", tag, tt.wantTag)
			}
			if cmd != tt.wantCmd {
				t.Errorf("ParseLine() cmd = %q, want %q", cmd, tt.wantCmd)
			}
			if len(args) != len(tt.wantArgs) {
				t.Errorf("ParseLine() args len = %d, want %d", len(args), len(tt.wantArgs))
			} else {
				for i := range args {
					if args[i] != tt.wantArgs[i] {
						t.Errorf("ParseLine() args[%d] = %q, want %q", i, args[i], tt.wantArgs[i])
					}
				}
			}
		})
	}
}

func TestUnquoteString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "not quoted",
			input: "password",
			want:  "password",
		},
		{
			name:  "simple quoted",
			input: `"password"`,
			want:  "password",
		},
		{
			name:  "empty quoted",
			input: `""`,
			want:  "",
		},
		{
			name:  "quoted with spaces",
			input: `"pass word"`,
			want:  "pass word",
		},
		{
			name:  "escaped backslash",
			input: `"foo\\bar"`,
			want:  `foo\bar`,
		},
		{
			name:  "escaped quote",
			input: `"foo\"bar"`,
			want:  `foo"bar`,
		},
		{
			name:  "escaped backslash before quote",
			input: `"foo\\\"bar"`,
			want:  `foo\"bar`,
		},
		{
			name:  "multiple escapes",
			input: `"\\\"\\\"\\\"zzz"`,
			want:  `\"\"\"zzz`,
		},
		{
			name:  "backslash at end",
			input: `"password\\"`,
			want:  `password\`,
		},
		{
			name:  "only backslashes",
			input: `"\\\\\\\\"`,
			want:  `\\\\`,
		},
		{
			name:  "complex password",
			input: `"pass\\word\"with\\\"escapes"`,
			want:  `pass\word"with\"escapes`,
		},
		{
			name:  "email address",
			input: `"user@example.com"`,
			want:  "user@example.com",
		},
		{
			name:  "single quote (not double quote)",
			input: "'password'",
			want:  "'password'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UnquoteString(tt.input)
			if got != tt.want {
				t.Errorf("UnquoteString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseLineUnquoteStringIntegration(t *testing.T) {
	// Test that ParseLine + UnquoteString work together correctly
	tests := []struct {
		name         string
		line         string
		wantUsername string
		wantPassword string
	}{
		{
			name:         "simple password",
			line:         `A001 LOGIN "user@example.com" "password"`,
			wantUsername: "user@example.com",
			wantPassword: "password",
		},
		{
			name:         "password with backslash",
			line:         `A001 LOGIN "user@example.com" "foo\\bar"`,
			wantUsername: "user@example.com",
			wantPassword: `foo\bar`,
		},
		{
			name:         "password with quote",
			line:         `A001 LOGIN "user@example.com" "foo\"bar"`,
			wantUsername: "user@example.com",
			wantPassword: `foo"bar`,
		},
		{
			name:         "password with backslash-quote",
			line:         `A001 LOGIN "user@example.com" "foo\\\"bar"`,
			wantUsername: "user@example.com",
			wantPassword: `foo\"bar`,
		},
		{
			name:         "complex password",
			line:         `A001 LOGIN "service@abgeordnetenwatch.de" "my\\pass\"word"`,
			wantUsername: "service@abgeordnetenwatch.de",
			wantPassword: `my\pass"word`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, cmd, args, err := ParseLine(tt.line, true)
			if err != nil {
				t.Fatalf("ParseLine() error: %v", err)
			}
			if cmd != "LOGIN" {
				t.Fatalf("ParseLine() cmd = %q, want LOGIN", cmd)
			}
			if len(args) != 2 {
				t.Fatalf("ParseLine() len(args) = %d, want 2", len(args))
			}

			username := UnquoteString(args[0])
			password := UnquoteString(args[1])

			if username != tt.wantUsername {
				t.Errorf("username = %q, want %q", username, tt.wantUsername)
			}
			if password != tt.wantPassword {
				t.Errorf("password = %q, want %q", password, tt.wantPassword)
			}

			_ = tag // Unused in this test
		})
	}
}
