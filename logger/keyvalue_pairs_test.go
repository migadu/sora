package logger

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Structured log calls take key/value pairs after the message. A key slog cannot use
// turns the pair into "!BADKEY=<value>", or makes a value the next pair's key, so the
// field cannot be filtered on (#299: the POP3 session memory limit error, the HTTP-01
// server error, a printf-style ConnectionManager line). This guard checks every
// logger.Debug/Info/Warn/Error call (and their Context forms) and every session
// DebugLog/InfoLog/WarnLog/ErrorLog call: each key must be a string literal followed by
// its value, or a slog.Attr built in place (slog.String, slog.Any, ...).
func TestLogCallsPassKeyValuePairs(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	loggerFuncs := map[string]int{ // name -> index of the first key/value argument
		"Debug": 1, "Info": 1, "Warn": 1, "Error": 1,
		"DebugContext": 2, "InfoContext": 2, "WarnContext": 2, "ErrorContext": 2,
	}
	sessionMethods := map[string]bool{"DebugLog": true, "InfoLog": true, "WarnLog": true, "ErrorLog": true}

	fset := token.NewFileSet()
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || call.Ellipsis.IsValid() {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			first := -1
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "logger" {
				if i, ok := loggerFuncs[sel.Sel.Name]; ok {
					first = i
				}
			} else if sessionMethods[sel.Sel.Name] {
				first = 1
			}
			if first < 0 || len(call.Args) < first {
				return true
			}
			if problem := keyValueProblem(call.Args[first:]); problem != "" {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, fmt.Sprintf("%s:%d: %s", rel, fset.Position(call.Pos()).Line, problem))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("log calls whose arguments are not key/value pairs:\n%s", strings.Join(offenders, "\n"))
	}
}

// keyValueProblem describes the first argument of args that is not where a key/value
// pair or an slog.Attr belongs, or returns "" when there is none.
func keyValueProblem(args []ast.Expr) string {
	for i := 0; i < len(args); {
		if call, ok := args[i].(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "slog" {
					i++ // an slog.Attr takes one argument
					continue
				}
			}
		}
		if key, ok := args[i].(*ast.BasicLit); !ok || key.Kind != token.STRING {
			return fmt.Sprintf("argument %d is not a string literal key", i+1)
		}
		if i+1 == len(args) {
			return fmt.Sprintf("key %s has no value", args[i].(*ast.BasicLit).Value)
		}
		i += 2
	}
	return ""
}
