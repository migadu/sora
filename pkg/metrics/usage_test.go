package metrics

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const metricsImportPath = "github.com/migadu/sora/pkg/metrics"

// metricUses parses every non-test Go file of the module and returns, for each
// package-level metric declared in this package (a var initialised by a promauto
// constructor), the module-relative directories that reference it. A declaration
// does not count as a reference; a reference from inside this package (a helper
// such as TrackDomainCommand) does.
func metricUses(t *testing.T) (declared []string, uses map[string]map[string]bool) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := wd
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("go.mod not found above the metrics package")
		}
		root = parent
	}

	fset := token.NewFileSet()
	uses = make(map[string]map[string]bool)
	use := func(name, dir string) {
		if uses[name] == nil {
			uses[name] = make(map[string]bool)
		}
		uses[name][dir] = true
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		dir, _ := filepath.Rel(root, filepath.Dir(path))
		dir = filepath.ToSlash(dir)

		if dir == "pkg/metrics" {
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ValueSpec:
					// The names are declarations; the values may reference other metrics.
					for i, name := range x.Names {
						if i < len(x.Values) && isPromautoCall(x.Values[i]) {
							declared = append(declared, name.Name)
						}
					}
					for _, v := range x.Values {
						ast.Inspect(v, func(n ast.Node) bool {
							if id, ok := n.(*ast.Ident); ok {
								use(id.Name, dir)
							}
							return true
						})
					}
					return false
				case *ast.Ident:
					use(x.Name, dir)
				}
				return true
			})
			return nil
		}

		local := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == metricsImportPath {
				local = "metrics"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		if local == "" {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == local {
					use(sel.Sel.Name, dir)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(declared) == 0 {
		t.Fatal("found no promauto metric declarations; the scan is broken")
	}
	return declared, uses
}

func isPromautoCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "promauto"
}

// TestEveryMetricIsRecordedOutsideTests: a registered metric that no code updates is
// still exported, an unlabelled one as a constant 0 that reads like a healthy value
// (no pool waits, no lock waits, no slow operations). Every metric must be updated
// somewhere outside tests, or not exist.
func TestEveryMetricIsRecordedOutsideTests(t *testing.T) {
	declared, uses := metricUses(t)

	var dead []string
	for _, name := range declared {
		if len(uses[name]) == 0 {
			dead = append(dead, name)
		}
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Errorf("%d metrics are registered but never updated outside tests:\n  %s",
			len(dead), strings.Join(dead, "\n  "))
	}
}

// TestCacheOperationsCountOnlyTheBodyCache: sora_cache_operations_total is the local
// message body cache's hit/miss counter. The proxies' lookup caches (logins and
// routing) have their own metrics; counting them here too made the body cache's hit
// ratio a blend of message reads and logins.
func TestCacheOperationsCountOnlyTheBodyCache(t *testing.T) {
	_, uses := metricUses(t)

	var others []string
	for dir := range uses["CacheOperationsTotal"] {
		if dir != "cache" {
			others = append(others, dir)
		}
	}
	sort.Strings(others)
	if len(others) > 0 {
		t.Errorf("CacheOperationsTotal is updated outside the body cache, by:\n  %s",
			strings.Join(others, "\n  "))
	}
}
