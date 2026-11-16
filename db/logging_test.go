package db

import (
	"bytes"
	"go/parser"
	"go/token"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/logger"
)

// The db package logs through the logger package. The standard log package reaches the
// configured output only at INFO, so a line that says "ERROR" or "WARNING" could not be
// filtered by level and carried no fields (#299).
func TestDBPackageDoesNotImportStdlibLog(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "log" {
				t.Errorf("%s imports the standard log package; use github.com/migadu/sora/logger", path)
			}
		}
	}
}

// A keyword SplitFlags drops is reported at WARN, with the keyword as a field.
func TestSplitFlagsWarnsAboutDroppedKeywords(t *testing.T) {
	var logs bytes.Buffer
	prev := logger.Swap(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { logger.Swap(prev) })

	tooLong := strings.Repeat("k", FlagsMaxKeywordLength+1)
	_, keywords := SplitFlags([]imap.Flag{"not(atom)", imap.Flag(tooLong), "$Kept"})
	if len(keywords) != 1 || keywords[0] != "$Kept" {
		t.Fatalf("keywords = %v, want [$Kept]", keywords)
	}

	out := logs.String()
	for _, want := range []string{"keyword=not(atom)", "keyword=" + tooLong} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no WARN record with %s; log:\n%s", want, out)
		}
	}
}
