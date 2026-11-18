package sora

import (
	"bytes"
	"go/format"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestGoFilesAreGofmtFormatted: every Go file in the repository is gofmt-clean, so
// `gofmt -l` on a touched package lists only the author's own changes (#1935). Only
// git-tracked files are checked, so untracked work in a checkout cannot fail it.
func TestGoFilesAreGofmtFormatted(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	out, err := exec.Command("git", "ls-files", "-z", "--", "*.go").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}

	var unformatted []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p == "" || strings.HasPrefix(p, "vendor/") || strings.Contains("/"+p, "/testdata/") {
			continue
		}
		src, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue // deleted in the working tree, not yet committed
		}
		if err != nil {
			t.Fatal(err)
		}
		formatted, err := format.Source(src)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if !bytes.Equal(src, formatted) {
			unformatted = append(unformatted, p)
		}
	}
	if len(unformatted) > 0 {
		t.Errorf("not gofmt-formatted (run gofmt -w on them):\n%s", strings.Join(unformatted, "\n"))
	}
}
