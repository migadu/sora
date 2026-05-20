package server

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadBoundedLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxBytes int
		wantLine string
		wantErr  error
	}{
		{
			name:     "normal line within limit",
			input:    "HELLO WORLD\n",
			maxBytes: 100,
			wantLine: "HELLO WORLD\n",
			wantErr:  nil,
		},
		{
			name:     "line at exact limit",
			input:    "12345\n", // 6 bytes
			maxBytes: 6,
			wantLine: "12345\n",
			wantErr:  nil,
		},
		{
			name:     "line exceeds limit by 1",
			input:    "1234567\n", // 8 bytes
			maxBytes: 7,
			wantLine: "",
			wantErr:  ErrLineTooLong,
		},
		{
			name:     "empty line",
			input:    "\n",
			maxBytes: 10,
			wantLine: "\n",
			wantErr:  nil,
		},
		{
			name:     "line without newline (EOF)",
			input:    "HELLO",
			maxBytes: 10,
			wantLine: "HELLO",
			wantErr:  nil,
		},
		{
			name:     "line without newline exceeds limit",
			input:    "HELLO WORLD",
			maxBytes: 5,
			wantLine: "",
			wantErr:  ErrLineTooLong,
		},
		{
			name:     "very long line exceeds limit",
			input:    strings.Repeat("A", 10000) + "\n",
			maxBytes: 1024,
			wantLine: "",
			wantErr:  ErrLineTooLong,
		},
		{
			name:     "CR LF line",
			input:    "HELLO\r\n",
			maxBytes: 100,
			wantLine: "HELLO\r\n",
			wantErr:  nil,
		},
		{
			name:     "multiple lines - first within limit",
			input:    "FIRST\nSECOND\n",
			maxBytes: 100,
			wantLine: "FIRST\n",
			wantErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.input))
			gotLine, gotErr := ReadBoundedLine(reader, tt.maxBytes)

			if gotErr != tt.wantErr {
				t.Errorf("ReadBoundedLine() error = %v, wantErr %v", gotErr, tt.wantErr)
				return
			}
			if gotLine != tt.wantLine {
				t.Errorf("ReadBoundedLine() line = %q, want %q", gotLine, tt.wantLine)
			}
		})
	}
}

func TestReadBoundedLine_BufferBoundary(t *testing.T) {
	// Test that we handle buffer boundaries correctly
	// bufio.Reader default buffer is 4096 bytes
	tests := []struct {
		name     string
		lineSize int
		maxBytes int
		wantErr  error
	}{
		{
			name:     "line just under buffer size",
			lineSize: 4095,
			maxBytes: 5000,
			wantErr:  nil,
		},
		{
			name:     "line exceeds buffer but within max",
			lineSize: 5000,
			maxBytes: 6000,
			wantErr:  nil,
		},
		{
			name:     "line exceeds both buffer and max",
			lineSize: 5000,
			maxBytes: 1024,
			wantErr:  ErrLineTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.Repeat("A", tt.lineSize) + "\n"
			reader := bufio.NewReader(strings.NewReader(input))
			_, gotErr := ReadBoundedLine(reader, tt.maxBytes)

			if gotErr != tt.wantErr {
				t.Errorf("ReadBoundedLine() error = %v, wantErr %v", gotErr, tt.wantErr)
			}
		})
	}
}

func TestReadBoundedLine_SequentialReads(t *testing.T) {
	// Test that we can read multiple lines correctly
	input := "FIRST\nSECOND\nTHIRD\n"
	reader := bufio.NewReader(strings.NewReader(input))

	line1, err1 := ReadBoundedLine(reader, 100)
	if err1 != nil || line1 != "FIRST\n" {
		t.Errorf("First read: got %q, %v; want %q, nil", line1, err1, "FIRST\n")
	}

	line2, err2 := ReadBoundedLine(reader, 100)
	if err2 != nil || line2 != "SECOND\n" {
		t.Errorf("Second read: got %q, %v; want %q, nil", line2, err2, "SECOND\n")
	}

	line3, err3 := ReadBoundedLine(reader, 100)
	if err3 != nil || line3 != "THIRD\n" {
		t.Errorf("Third read: got %q, %v; want %q, nil", line3, err3, "THIRD\n")
	}
}
