package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryS3ClientSignsForTheConfiguredRegion: a client built without
// storage.WithRegion signs for AWS_REGION or us-east-1 instead of the configured
// region, and AWS refuses that signature for a bucket in another region. The server
// and every other command would work while that one command failed, so every
// storage.New call in sora-admin and the server must pass the region.
func TestEveryS3ClientSignsForTheConfiguredRegion(t *testing.T) {
	var missing []string
	for _, dir := range []string{".", filepath.Join("..", "sora")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isStorageCall(call.Fun, "New") {
					return true
				}
				for _, arg := range call.Args {
					if inner, ok := arg.(*ast.CallExpr); ok && isStorageCall(inner.Fun, "WithRegion") {
						return true
					}
				}
				missing = append(missing, fset.Position(call.Pos()).String())
				return true
			})
		}
	}
	for _, pos := range missing {
		t.Errorf("%s: storage.New without storage.WithRegion", pos)
	}
}

func isStorageCall(fun ast.Expr, name string) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "storage"
}
