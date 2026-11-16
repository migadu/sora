package helpers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestIngestPathsShareTheFTSBodyRule: every path that stores a message (LMTP, IMAP
// APPEND, Admin API delivery, sora-admin import maildir and import s3) must take the
// text it stores for full-text search from one rule. ExtractPlaintextBody returns
// text and an error together when it skipped a part; each caller deciding for itself
// what that means is how three of five came to store "" for such a message, which
// was then searchable only when LMTP delivered it (#1808).
func TestIngestPathsShareTheFTSBodyRule(t *testing.T) {
	fset := token.NewFileSet()
	var offenders []string
	for _, dir := range []string{"cmd", "db", "pkg", "server"} {
		err := filepath.WalkDir(filepath.Join("..", dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "ExtractPlaintextBody" {
					offenders = append(offenders, fset.Position(sel.Pos()).String())
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("ExtractPlaintextBody called outside helpers; store helpers.FTSPlaintextBody instead:\n%s",
			strings.Join(offenders, "\n"))
	}
}
