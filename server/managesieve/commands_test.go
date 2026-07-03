package managesieve

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

func TestHandleCheckScript(t *testing.T) {
	addr, err := server.NewAddress("test@example.com")
	if err != nil {
		t.Fatalf("NewAddress failed: %v", err)
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	session := &ManageSieveSession{
		Session: server.Session{
			User: server.NewUser(addr, 123),
		},
		authenticated: true,
		ctx:           context.Background(),
		writer:        writer,
		server: &ManageSieveServer{
			maxScriptSize:       1024,
			supportedExtensions: []string{"fileinto"},
		},
	}

	tests := []struct {
		name         string
		content      string
		wantSuccess  bool
		wantResponse string
	}{
		{
			name:         "Valid script",
			content:      "keep;",
			wantSuccess:  true,
			wantResponse: "OK\r\n",
		},
		{
			name:         "Invalid script syntax",
			content:      "invalid_command;",
			wantSuccess:  false,
			wantResponse: "NO \"Script validation failed",
		},
		{
			name:         "Script exceeding size limit",
			content:      strings.Repeat("a", 2000),
			wantSuccess:  false,
			wantResponse: "NO (QUOTA/MAXSIZE)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			got := session.handleCheckScript(tt.content)
			writer.Flush()

			if got != tt.wantSuccess {
				t.Errorf("handleCheckScript() = %v, want %v", got, tt.wantSuccess)
			}
			resp := buf.String()
			if !strings.Contains(resp, tt.wantResponse) {
				t.Errorf("Response = %q, want it to contain %q", resp, tt.wantResponse)
			}
		})
	}
}

func TestHandleHaveSpace(t *testing.T) {
	addr, err := server.NewAddress("test@example.com")
	if err != nil {
		t.Fatalf("NewAddress failed: %v", err)
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	session := &ManageSieveSession{
		Session: server.Session{
			User: server.NewUser(addr, 123),
		},
		authenticated: true,
		ctx:           context.Background(),
		writer:        writer,
		server: &ManageSieveServer{
			maxScriptSize: 1024,
		},
	}

	tests := []struct {
		name         string
		size         int64
		wantSuccess  bool
		wantResponse string
	}{
		{
			name:         "Within limit",
			size:         512,
			wantSuccess:  true,
			wantResponse: "OK\r\n",
		},
		{
			name:         "Exceeds limit",
			size:         2048,
			wantSuccess:  false,
			wantResponse: "NO (QUOTA/MAXSIZE)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			got := session.handleHaveSpace("myscript", tt.size)
			writer.Flush()

			if got != tt.wantSuccess {
				t.Errorf("handleHaveSpace() = %v, want %v", got, tt.wantSuccess)
			}
			resp := buf.String()
			if !strings.Contains(resp, tt.wantResponse) {
				t.Errorf("Response = %q, want it to contain %q", resp, tt.wantResponse)
			}
		})
	}
}
