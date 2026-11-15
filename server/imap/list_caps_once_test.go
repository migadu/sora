package imap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// LIST reads the session's capability set once (#1079). GetCapabilities returns
// a fresh copy of the set on every call, and the set cannot change in the middle
// of a command, so a call per listed mailbox (and another per mailbox for
// RETURN (STATUS ...)) only allocated garbage in proportion to the account's
// mailbox count on every LIST a client syncs with.
func TestList_ReadsCapabilitiesOnce(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "list.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var list *ast.FuncDecl
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "List" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
			if id, ok := star.X.(*ast.Ident); ok && id.Name == "IMAPSession" {
				list = fn
			}
		}
	}
	if list == nil {
		t.Fatal("(*IMAPSession).List not found in list.go")
	}

	var loops []ast.Node
	var calls []token.Pos
	ast.Inspect(list.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			loops = append(loops, n)
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "GetCapabilities" {
				calls = append(calls, n.Pos())
			}
		}
		return true
	})

	for _, pos := range calls {
		for _, loop := range loops {
			if loop.Pos() <= pos && pos < loop.End() {
				t.Errorf("List calls GetCapabilities inside a loop at %s (loop at %s)", fset.Position(pos), fset.Position(loop.Pos()))
			}
		}
	}
	if len(calls) != 1 {
		var at []string
		for _, pos := range calls {
			at = append(at, fset.Position(pos).String())
		}
		t.Errorf("List calls GetCapabilities %d times, want once: %v", len(calls), at)
	}
}
