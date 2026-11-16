package helpers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// TestFTSPlaintextBody: the text of the parts the extraction could read is kept
// beside the error naming the part it skipped, and a message without a text part,
// or none at all, gives "".
func TestFTSPlaintextBody(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "skipped part beside a text part",
			raw: "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n" +
				"Content-Type: multipart/mixed; boundary=b1\r\n\r\n" +
				"--b1\r\nContent-Type: image/png; name=a b.png\r\nContent-Disposition: inline\r\n\r\nPNG\r\n" +
				"--b1\r\nContent-Type: text/plain\r\n\r\nhello words\r\n--b1--\r\n",
			want:    "hello words",
			wantErr: true,
		},
		{
			name: "no text part",
			raw: "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n" +
				"Content-Type: application/octet-stream\r\n\r\nAAAA\r\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entity, err := message.Read(strings.NewReader(tc.raw))
			if err != nil {
				t.Fatalf("message.Read: %v", err)
			}
			text, err := FTSPlaintextBody(entity)
			if strings.TrimSpace(text) != tc.want {
				t.Errorf("FTSPlaintextBody = %q, want %q", text, tc.want)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("FTSPlaintextBody error = %v, want error %v", err, tc.wantErr)
			}
		})
	}

	t.Run("nil message", func(t *testing.T) {
		if text, err := FTSPlaintextBody(nil); text != "" || err == nil {
			t.Errorf("FTSPlaintextBody(nil) = %q, %v; want \"\" and an error", text, err)
		}
	})
}

// TestIngestPathsShareTheFTSBodyRule: every path that stores a message (LMTP, IMAP
// APPEND, Admin API delivery, sora-admin import maildir and import s3) must take the
// text it stores for full-text search from one rule. ExtractPlaintextBody returns
// text and an error together when it skipped a part; each caller deciding for itself
// what that means is how three of five came to store "" for such a message, which
// was then searchable only when LMTP delivered it (#1808).
func TestIngestPathsShareTheFTSBodyRule(t *testing.T) {
	fset := token.NewFileSet()
	var offenders []string
	for _, dir := range []string{"cmd", "db", "pkg", "server"} {
		err := filepath.WalkDir(filepath.Join("..", dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "ExtractPlaintextBody" {
					offenders = append(offenders, fset.Position(sel.Pos()).String())
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(offenders) > 0 {
		t.Errorf("ExtractPlaintextBody called outside helpers; store helpers.FTSPlaintextBody instead:\n%s",
			strings.Join(offenders, "\n"))
	}
}
