package managesieve

import (
	"encoding/base64"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
)

// isQuotedString reports whether s is an RFC 5804 section 4 quoted string:
//
//	quoted        = DQUOTE *1024QUOTED-CHAR DQUOTE
//	QUOTED-CHAR   = SAFE-UTF8-CHAR / "\" QUOTED-SPECIALS
//	QUOTED-SPECIALS = DQUOTE / "\"
func isQuotedString(s string) bool {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' || len(s)-2 > 1024 {
		return false
	}
	inner := s[1 : len(s)-1]
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '\r', '\n', 0:
			return false
		case '"':
			return false
		case '\\':
			if i+1 >= len(inner) || (inner[i+1] != '"' && inner[i+1] != '\\') {
				return false
			}
			i++
		}
	}
	return true
}

// A NO reply's text is a string (RFC 5804 section 4: response-nobye = ("NO" / "BYE")
// [SP "(" resp-code ")"] [SP string] CRLF; string = quoted / literal-c2s /
// literal-s2c). go-managesieve writes an uncoded *managesieveserver.Error message
// verbatim after "NO ", so the backend must pre-quote it (#336).
func TestNoRepliesAreQuotedStrings(t *testing.T) {
	cfg := config.ServerConfig{Name: "sieve-no-quoted", Type: "managesieve"}
	srv := newServerForConfig(t, cfg, ManageSieveServerOptions{
		MasterSASLUsername: "master",
		MasterSASLPassword: "secret",
	})
	plain := func(authz, authn, password string) string {
		return fmt.Sprintf(`AUTHENTICATE "PLAIN" "%s"`, base64.StdEncoding.EncodeToString([]byte(authz+"\x00"+authn+"\x00"+password)))
	}
	for _, tt := range []struct {
		name, command, want string
	}{
		{"wrong master SASL password", plain("user@example.com", "master", "wrong"), `NO "Authentication failed"`},
		{"unparsable identity", plain("", "not-an-address", "password"), `NO "Authentication failed"`},
		{"authorization identity without master SASL", plain("other@example.com", "user@example.com", "password"),
			`NO "Proxy authentication requires master_sasl_username and master_sasl_password to be configured"`},
		{"LOGIN with an unparsable address", `LOGIN "not-an-address" "password"`, `NO "Authentication failed"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, reader, _ := dialManageSieve(t, srv)
			if _, err := conn.Write([]byte(tt.command + "\r\n")); err != nil {
				t.Fatal(err)
			}
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("reading the reply: %v", err)
			}
			if got := strings.TrimRight(line, "\r\n"); got != tt.want {
				t.Errorf("reply = %q, want %q", got, tt.want)
			}
		})
	}
}

// Every uncoded *managesieveserver.Error the backend builds carries a quoted string,
// including the replies a test cannot easily provoke (server busy, session closed, a
// full delay queue, a login cut short during its delay). A coded one is quoted by the
// library.
func TestUncodedErrorMessagesArePreQuoted(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, file, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Error" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "managesieveserver" {
				return true
			}
			var code, message ast.Expr
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "Code":
					code = kv.Value
				case "Message":
					message = kv.Value
				}
			}
			if code != nil {
				return true
			}
			checked++
			pos := fset.Position(lit.Pos())
			switch m := message.(type) {
			case *ast.BasicLit:
				if v, err := strconv.Unquote(m.Value); err != nil || !isQuotedString(v) {
					t.Errorf("%s: uncoded NO text %s is not a quoted string", pos, m.Value)
				}
			case *ast.CallExpr:
				if s, ok := m.Fun.(*ast.SelectorExpr); !ok || s.Sel.Name != "Quote" {
					t.Errorf("%s: uncoded NO text %s is not passed through Quote", pos, src[m.Pos()-f.FileStart:m.End()-f.FileStart])
				}
			default:
				t.Errorf("%s: uncoded NO text is not a pre-quoted string (got %T)", pos, message)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("found no uncoded managesieveserver.Error literal; the scan is broken")
	}
}
