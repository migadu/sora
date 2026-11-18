package sora

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// maxTestSleep is the longest constant sleep a test may take on its own goroutine. A wait
// this long is a test waiting out a production timer in real time (the proxy's one-minute
// backend quarantine, a circuit breaker's open timeout). White-box tests reach those timers:
// backdate the timestamp the timer reads or inject a shorter setting (#2055). The longest
// legitimate waits in the tree are a little over a server poll interval (16 s).
const maxTestSleep = 30 * time.Second

// longTestSleepAllowed lists the tests (file and function) that must wait out a timer they
// cannot reach, with the reason.
var longTestSleepAllowed = map[string]string{
	"integration_tests/imapproxy/pools_failover_test.go:TestIMAPProxyStickyFailoverSurvivesQuarantine": "black-box through a real proxy: the one-minute quarantine is the behaviour under test and is not configurable",
}

// TestNoTestSleepsLongerThanMaxTestSleep: no test sleeps maxTestSleep or longer on the test
// goroutine (time.Sleep or a bare <-time.After), counting durations built from literals and
// constants. Sleeps inside `go` statements do not hold the test and are not counted (a fake
// backend that stays silent). Only git-tracked files are checked, so untracked work in a
// checkout cannot fail it.
func TestNoTestSleepsLongerThanMaxTestSleep(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	out, err := exec.Command("git", "ls-files", "-z", "--", "*.go").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}

	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	consts := map[string]map[string]ast.Expr{} // directory -> package-level constant -> value
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
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		files[p] = f
		dir := path.Dir(p)
		if consts[dir] == nil {
			consts[dir] = map[string]ast.Expr{}
		}
		for _, decl := range f.Decls {
			collectConsts(decl, consts[dir])
		}
	}

	var long []string
	for p, f := range files {
		if !strings.HasSuffix(p, "_test.go") {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			scope := constScope{pkg: consts[path.Dir(p)], local: map[string]ast.Expr{}}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if ds, ok := n.(*ast.DeclStmt); ok {
					collectConsts(ds.Decl, scope.local)
				}
				return true
			})
			report := func(call *ast.CallExpr) {
				if len(call.Args) != 1 {
					return
				}
				d, ok := constDuration(call.Args[0], scope, 0)
				if !ok || d < float64(maxTestSleep) {
					return
				}
				if _, ok := longTestSleepAllowed[p+":"+fn.Name.Name]; ok {
					return
				}
				long = append(long, fset.Position(call.Pos()).String()+" "+fn.Name.Name+": "+time.Duration(d).String())
			}
			// time.Sleep, or a receive from time.After that is a statement of its own.
			var walk func(ast.Node) bool
			walk = func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.GoStmt:
					return false // does not hold the test
				case *ast.CommClause:
					// A select case's <-time.After is a timeout, not a sleep: walk only the body.
					for _, s := range n.Body {
						ast.Inspect(s, walk)
					}
					return false
				case *ast.ExprStmt:
					if u, ok := n.X.(*ast.UnaryExpr); ok && u.Op == token.ARROW {
						if call, ok := ast.Unparen(u.X).(*ast.CallExpr); ok && isTimeCall(call, "After") {
							report(call)
						}
					}
				case *ast.CallExpr:
					if isTimeCall(n, "Sleep") {
						report(n)
					}
				}
				return true
			}
			ast.Inspect(fn.Body, walk)
		}
	}
	if len(long) > 0 {
		sort.Strings(long)
		t.Errorf("tests sleeping %s or longer (backdate the timer's timestamp or inject a shorter setting):\n%s",
			maxTestSleep, strings.Join(long, "\n"))
	}
}

func collectConsts(decl ast.Decl, into map[string]ast.Expr) {
	gd, ok := decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.CONST {
		return
	}
	for _, spec := range gd.Specs {
		vs := spec.(*ast.ValueSpec)
		if len(vs.Values) != len(vs.Names) {
			continue // iota lists and implicit repetition: not durations here
		}
		for i, name := range vs.Names {
			into[name.Name] = vs.Values[i]
		}
	}
}

func isTimeCall(call *ast.CallExpr, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "time"
}

// constScope resolves a constant name: the function's own constants, then the package's.
type constScope struct{ pkg, local map[string]ast.Expr }

func (s constScope) lookup(name string) (ast.Expr, bool) {
	if v, ok := s.local[name]; ok {
		return v, true
	}
	v, ok := s.pkg[name]
	return v, ok
}

var timeUnits = map[string]time.Duration{
	"Nanosecond": time.Nanosecond, "Microsecond": time.Microsecond, "Millisecond": time.Millisecond,
	"Second": time.Second, "Minute": time.Minute, "Hour": time.Hour,
}

// constDuration evaluates e as a constant duration in nanoseconds, from literals, time units
// and the constants in scope. ok is false for anything else (variables, calls).
func constDuration(e ast.Expr, scope constScope, depth int) (float64, bool) {
	if depth > 16 {
		return 0, false
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.INT && e.Kind != token.FLOAT {
			return 0, false
		}
		v, err := strconv.ParseFloat(strings.ReplaceAll(e.Value, "_", ""), 64)
		return v, err == nil
	case *ast.ParenExpr:
		return constDuration(e.X, scope, depth+1)
	case *ast.Ident:
		v, ok := scope.lookup(e.Name)
		if !ok {
			return 0, false
		}
		return constDuration(v, scope, depth+1)
	case *ast.SelectorExpr:
		if pkg, ok := e.X.(*ast.Ident); ok && pkg.Name == "time" {
			if u, ok := timeUnits[e.Sel.Name]; ok {
				return float64(u), true
			}
		}
		return 0, false
	case *ast.CallExpr:
		if isTimeCall(e, "Duration") && len(e.Args) == 1 {
			return constDuration(e.Args[0], scope, depth+1)
		}
		return 0, false
	case *ast.BinaryExpr:
		x, ok := constDuration(e.X, scope, depth+1)
		if !ok {
			return 0, false
		}
		y, ok := constDuration(e.Y, scope, depth+1)
		if !ok {
			return 0, false
		}
		switch e.Op {
		case token.ADD:
			return x + y, true
		case token.SUB:
			return x - y, true
		case token.MUL:
			return x * y, true
		case token.QUO:
			if y == 0 {
				return 0, false
			}
			return x / y, true
		}
	}
	return 0, false
}
