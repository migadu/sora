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

// TestNoUnconditionallySkippedTests: no Test function, and no subtest (a func literal
// passed to t.Run), starts with a t.Skip, t.Skipf or t.SkipNow outside a condition,
// because such a test never runs and its failures go unseen (#1992, #2102). Skipping on testing.Short(), an environment variable, the OS and so
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
	for _, name := range []string{"a", "b"} {
		t.Run(name, func(st *testing.T) { st.Skip("not implemented") })
	}
	t.Run("short", func(t *testing.T) {
		if testing.Short() {
			t.Skip("short")
		}
	})
	t.Run("issue", func(t *testing.T) { t.Skip("see #2052") })
	t.Run("named", namedSubtest)
}
func helper(t *testing.T) {
	t.Skip("not a test")
	t.Run("in a helper", func(t *testing.T) { t.SkipNow() })
}
func BenchmarkSub(b *testing.B) { b.Run("x", func(b *testing.B) { b.Skip("benchmark") }) }
func BenchmarkX(b *testing.B) { b.Skip("not a test") }
func TestOther(t *testing.T)  { other.Skip("someone else's Skip") }
`
	got, err := unconditionallySkippedTests("x_test.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"TestBare", "TestBareSkipf", "TestBareSkipNow", "TestSub subtest name", "helper subtest \"in a helper\""}
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
// for each Test function, and "file:line:col: Func subtest <name>" for each func literal
// passed to t.Run in any function, whose first statement is a skip on its own
// *testing.T and whose skip message names no issue.
func unconditionallySkippedTests(path string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var found []string
	// check records body when its first statement is an unconditional skip on tName.
	check := func(ft *ast.FuncType, body *ast.BlockStmt, what string) {
		tName := testingTParam(ft)
		if tName == "" || body == nil || len(body.List) == 0 {
			return
		}
		call := skipCall(body.List[0], tName)
		if call == nil {
			return
		}
		// The message's source text, so a message built with + is read whole.
		if skipIssueRef.Match(src[fset.Position(call.Lparen).Offset:fset.Position(call.Rparen).Offset]) {
			return
		}
		found = append(found, fset.Position(call.Pos()).String()+": "+what)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
			check(fn.Type, fn.Body, fn.Name.Name)
		}
		// Subtests: t.Run(name, func(t *testing.T) { ... }), wherever they are started.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Run" {
				return true
			}
			if lit, ok := call.Args[1].(*ast.FuncLit); ok {
				name := src[fset.Position(call.Args[0].Pos()).Offset:fset.Position(call.Args[0].End()).Offset]
				check(lit.Type, lit.Body, fn.Name.Name+" subtest "+string(name))
			}
			return true
		})
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
