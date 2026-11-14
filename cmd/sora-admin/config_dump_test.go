package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runConfigDump runs `sora-admin --config path config dump` and returns its output.
func runConfigDump(t *testing.T, path string) string {
	t.Helper()
	args, stdout := os.Args, os.Stdout
	t.Cleanup(func() { os.Args, os.Stdout = args, stdout })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	os.Args = []string{"sora-admin", "--config", path, "config", "dump"}
	os.Stdout = w
	handleConfigDump(context.Background())
	os.Stdout = stdout
	w.Close()
	return <-out
}

// `config dump` shows the configuration the server runs with. A [database.write] or
// [database.read] endpoint the file does not define is not one the server uses (a
// proxy runs without a database); the dump used to show the built-in localhost one.
func TestConfigDumpShowsTheDatabaseEndpointsTheServerUses(t *testing.T) {
	for _, tc := range []struct {
		name, toml          string
		wantWrite, wantRead bool
	}{
		{"no endpoint", "[database]\nquery_timeout = \"10s\"\n", false, false},
		{"write endpoint only", "[database.write]\nhosts = [\"db1.example.com\"]\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			dump := runConfigDump(t, path)
			if got := strings.Contains(dump, "[database.write]"); got != tc.wantWrite {
				t.Errorf("dump shows [database.write]: %v, want %v\n%s", got, tc.wantWrite, dump)
			}
			if got := strings.Contains(dump, "[database.read]"); got != tc.wantRead {
				t.Errorf("dump shows [database.read]: %v, want %v\n%s", got, tc.wantRead, dump)
			}
			// A table in the file takes the server's defaults for the keys it leaves out.
			if tc.wantWrite && !strings.Contains(dump, `name = "sora_mail_db"`) {
				t.Errorf("dump does not show the default database name for [database.write]:\n%s", dump)
			}
		})
	}
}
