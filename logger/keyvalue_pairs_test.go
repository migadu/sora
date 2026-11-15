package logger

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Structured log calls take key/value pairs after the message. A key slog cannot use
// turns the pair into "!BADKEY=<value>", or makes a value the next pair's key, so the
// field cannot be filtered on (#299: the POP3 session memory limit error, the HTTP-01
// server error, a printf-style ConnectionManager line). This guard checks every
// logger.Debug/Info/Warn/Error/Fatal call (and their Context forms), every logger.With
// call, the same functions of log/slog, and every session DebugLog/InfoLog/WarnLog/
// ErrorLog call: each key must be a string literal followed by its value, or a
// slog.Attr built in place (slog.String, slog.Any, ...).
func TestLogCallsPassKeyValuePairs(t *testing.T) {
	var offenders []string
	for _, c := range logCalls(t) {
		if problem := keyValueProblem(c.args); problem != "" {
			offenders = append(offenders, c.pos+": "+problem)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("log calls whose arguments are not key/value pairs:\n%s", strings.Join(offenders, "\n"))
	}
}

// The JSON and text handlers write the record's own time, level and message under
// "time", "level" and "msg" and do not rename an attribute of the same name, so an
// attribute called level or msg makes a JSON record carry that name twice (#1000).
// RFC 8259 §4 leaves such an object to the receiver ("Many implementations report the
// last name/value pair only"), and a collector that keeps the last one files the
// record under the attribute's level or message. "source" is not reserved here: the
// handlers run without AddSource.
func TestLogCallsDoNotReuseRecordKeys(t *testing.T) {
	reserved := map[string]bool{slog.TimeKey: true, slog.LevelKey: true, slog.MessageKey: true}
	var offenders []string
	for _, c := range logCalls(t) {
		for _, key := range literalKeys(c.args) {
			if reserved[key] {
				offenders = append(offenders, fmt.Sprintf("%s: key %q", c.pos, key))
			}
		}
	}
	if len(offenders) > 0 {
		t.Errorf("log calls with an attribute named like the record's own time, level or message key:\n%s", strings.Join(offenders, "\n"))
	}
}

// TestLiteralKeys checks that the record-key guard sees the keys of both pair and
// slog.Attr arguments.
func TestLiteralKeys(t *testing.T) {
	expr, err := parser.ParseExpr(`f("a", 1, slog.String("level", "x"), "msg", y, slog.Group("time", "b", 2), "c", z)`)
	if err != nil {
		t.Fatal(err)
	}
	got := literalKeys(expr.(*ast.CallExpr).Args)
	want := []string{"a", "level", "msg", "time", "c"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("literalKeys = %q, want %q", got, want)
	}
}

// TestFileLogCalls checks that the walk finds the logger package under an alias and
// log/slog's own functions, and does not take a variable called logger for the package.
func TestFileLogCalls(t *testing.T) {
	const src = `package p

import (
	"log/slog"

	soralogger "github.com/migadu/sora/logger"
)

func f(s *session, logger *other) {
	soralogger.Info("a", "k1", 1)
	slog.Warn("b", "k2", 2)
	s.InfoLog("c", "k3", 3)
	logger.Info("d", "k4", 4)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range fileLogCalls(fset, "p.go", file) {
		got = append(got, c.pos+" "+strings.Join(literalKeys(c.args), ","))
	}
	want := []string{"p.go:10 k1", "p.go:11 k2", "p.go:12 k3"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("fileLogCalls = %q, want %q", got, want)
	}
}

// logCall is a structured log call found in the module's non-test sources: where it
// is, and its arguments after the message.
type logCall struct {
	pos  string
	args []ast.Expr
}

// logCalls parses every non-test Go file of the module and returns its log calls (see
// fileLogCalls).
func logCalls(t *testing.T) []logCall {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var calls []logCall
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
		rel, _ := filepath.Rel(root, path)
		calls = append(calls, fileLogCalls(fset, rel, file)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) == 0 {
		t.Fatal("found no log calls; the walk is not looking at the module's sources")
	}
	return calls
}

// fileLogCalls returns the structured log calls of file, named name in the positions:
// the logger package's Debug/Info/Warn/Error/Fatal (and their Context forms) and With,
// the same functions of log/slog, and every session DebugLog/InfoLog/WarnLog/ErrorLog
// method. The packages are recognised by import path, so an aliased import
// (server/delivery imports the logger as soralogger) is covered as well. Calls that
// spread a slice (args...) are left out: their keys are not visible in the source.
func fileLogCalls(fset *token.FileSet, name string, file *ast.File) []logCall {
	loggerFuncs := map[string]int{ // name -> index of the first key/value argument
		"Debug": 1, "Info": 1, "Warn": 1, "Error": 1, "Fatal": 1,
		"DebugContext": 2, "InfoContext": 2, "WarnContext": 2, "ErrorContext": 2,
		"With": 0,
	}
	sessionMethods := map[string]bool{"DebugLog": true, "InfoLog": true, "WarnLog": true, "ErrorLog": true}
	defaultNames := map[string]string{"github.com/migadu/sora/logger": "logger", "log/slog": "slog"}
	logPackages := map[string]bool{} // the names file refers to those packages by
	for _, imp := range file.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil || defaultNames[importPath] == "" {
			continue
		}
		if imp.Name != nil {
			logPackages[imp.Name.Name] = true
		} else {
			logPackages[defaultNames[importPath]] = true
		}
	}

	var calls []logCall
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
		if pkg, ok := sel.X.(*ast.Ident); ok && logPackages[pkg.Name] {
			if i, ok := loggerFuncs[sel.Sel.Name]; ok {
				first = i
			}
		} else if sessionMethods[sel.Sel.Name] {
			first = 1
		}
		if first < 0 || len(call.Args) < first {
			return true
		}
		calls = append(calls, logCall{
			pos:  fmt.Sprintf("%s:%d", name, fset.Position(call.Pos()).Line),
			args: call.Args[first:],
		})
		return true
	})
	return calls
}

// keyValueProblem describes the first argument of args that is not where a key/value
// pair or an slog.Attr belongs, or returns "" when there is none.
func keyValueProblem(args []ast.Expr) string {
	for i := 0; i < len(args); {
		if slogCall(args[i]) != nil {
			i++ // an slog.Attr takes one argument
			continue
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

// literalKeys returns the attribute keys of args written as string literals: the key of
// each key/value pair and the first argument of each slog.String, slog.Group, ... call.
// It stops at the first argument keyValueProblem would report.
func literalKeys(args []ast.Expr) []string {
	var keys []string
	add := func(e ast.Expr) bool {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		if key, err := strconv.Unquote(lit.Value); err == nil {
			keys = append(keys, key)
		}
		return true
	}
	for i := 0; i < len(args); {
		if call := slogCall(args[i]); call != nil {
			if len(call.Args) > 0 {
				add(call.Args[0])
			}
			i++
			continue
		}
		if !add(args[i]) {
			break
		}
		i += 2
	}
	return keys
}

// slogCall returns e as a call of a log/slog package function (slog.String, slog.Any,
// ...), or nil.
func slogCall(e ast.Expr) *ast.CallExpr {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "slog" {
		return nil
	}
	return call
}
