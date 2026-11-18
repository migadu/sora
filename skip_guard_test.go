package sora

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// skipIssueRef is how an always-skipped test names the open issue that keeps it skipped.
var skipIssueRef = regexp.MustCompile(`#[0-9]+\b`)

// TestNoUnconditionallySkippedTests: no Test function starts with a t.Skip, t.Skipf or
// t.SkipNow outside a condition, because such a test never runs and its failures go
// unseen (#1992). Skipping on testing.Short(), an environment variable, the OS and so
// on is fine: the skip then sits inside an if. A test that must stay skipped until a
// defect is fixed names the open issue in its skip message ("see #1234"), and the fix
// removes the skip. Every git-tracked test file is parsed, whatever its build tags, so
// integration tests are covered without a database.
func TestNoUnconditionallySkippedTests(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	out, err := exec.Command("git", "ls-files", "-z", "--", "*_test.go").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}

	var skipped []string
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
		found, err := unconditionallySkippedTests(p, src)
		if err != nil {
			t.Errorf("%s: %v", p, err)
		}
		skipped = append(skipped, found...)
	}
	if len(skipped) > 0 {
		t.Errorf("tests that always skip (make them run, delete them, or name the open issue in the skip message, \"see #1234\"):\n%s",
			strings.Join(skipped, "\n"))
	}
}

// TestUnconditionallySkippedTestsDetector pins what the guard above counts as an
// always-skipped test, so a change to it cannot quietly pass everything.
func TestUnconditionallySkippedTestsDetector(t *testing.T) {
	const src = `package x

import "testing"

func TestBare(t *testing.T)         { t.Skip("not implemented") }
func TestBareSkipf(t *testing.T)    { t.Skipf("not %s", "implemented") }
func TestBareSkipNow(tt *testing.T) { tt.SkipNow(); tt.Log("never") }
func TestIssue(t *testing.T)        { t.Skip("ListObjects ignores cancellation; " + "see #2053") }
func TestShort(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
}
func TestNotFirst(t *testing.T) { t.Helper(); t.Skip("not the first statement") }
func TestSub(t *testing.T) {
	t.Run("x", func(t *testing.T) { t.Skip("subtests are not checked") })
}
func helper(t *testing.T)     { t.Skip("not a test") }
func BenchmarkX(b *testing.B) { b.Skip("not a test") }
func TestOther(t *testing.T)  { other.Skip("someone else's Skip") }
`
	got, err := unconditionallySkippedTests("x_test.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"TestBare", "TestBareSkipf", "TestBareSkipNow"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i, w := range want {
		if !strings.HasSuffix(got[i], ": "+w) {
			t.Errorf("got %q, want %q", got[i], w)
		}
	}
}

// unconditionallySkippedTests parses one test file and returns "file:line:col: TestName"
// for each Test function whose first statement is a skip on its own *testing.T and whose
// skip message names no issue.
func unconditionallySkippedTests(path string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var found []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || len(fn.Body.List) == 0 || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		tName := testingTParam(fn.Type)
		if tName == "" {
			continue
		}
		call := skipCall(fn.Body.List[0], tName)
		if call == nil {
			continue
		}
		// The message's source text, so a message built with + is read whole.
		args := src[fset.Position(call.Lparen).Offset:fset.Position(call.Rparen).Offset]
		if skipIssueRef.Match(args) {
			continue
		}
		found = append(found, fset.Position(call.Pos()).String()+": "+fn.Name.Name)
	}
	return found, nil
}

// testingTParam returns the name of a function's parameter when its only parameter is
// a *testing.T.
func testingTParam(ft *ast.FuncType) string {
	if ft.Params == nil || len(ft.Params.List) != 1 || len(ft.Params.List[0].Names) != 1 {
		return ""
	}
	star, ok := ft.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "T" {
		return ""
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "testing" {
		return ""
	}
	return ft.Params.List[0].Names[0].Name
}

// skipCall returns stmt as a call when it is tName.Skip, tName.Skipf or tName.SkipNow.
func skipCall(stmt ast.Stmt, tName string) *ast.CallExpr {
	es, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if recv, ok := sel.X.(*ast.Ident); !ok || recv.Name != tName {
		return nil
	}
	switch sel.Sel.Name {
	case "Skip", "Skipf", "SkipNow":
		return call
	}
	return nil
}
