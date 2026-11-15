package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

// TestStartupLogsMaskEndpointURLs: the relay's http_url, the spam training endpoint
// and the remote lookup URL may carry credentials in their userinfo or query, so no
// log call here is handed one as configured; it goes through
// config.MaskEndpointURL, as the config dump shows it (#806). start-up logged
// "Relay handler configured: type=http" and "Spam training client initialized" with
// the raw URL at INFO.
func TestStartupLogsMaskEndpointURLs(t *testing.T) {
	endpoints := []string{".Relay.HTTPURL", ".SpamTraining.Endpoint", ".RemoteLookup.URL"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fun, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := fun.X.(*ast.Ident); !ok || pkg.Name != "logger" {
				return true
			}
			for _, arg := range call.Args {
				expr := types.ExprString(arg)
				for _, endpoint := range endpoints {
					if strings.HasSuffix(expr, endpoint) {
						t.Errorf("%s: logger.%s logs %s unmasked; pass config.MaskEndpointURL(%s)",
							fset.Position(arg.Pos()), fun.Sel.Name, expr, expr)
					}
				}
			}
			return true
		})
	}
}
