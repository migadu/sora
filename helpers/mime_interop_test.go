package helpers

import "testing"

func TestAttachmentKeyword_HeaderCommentsAndTrailingSemicolons(t *testing.T) {
	for _, tc := range []struct{ name, headers, body, want string }{
		{"trailing type separator", "Content-Type: text/plain;", "body", "$hasnoattachment"},
		{"trailing separator after charset", `Content-Type: text/plain; charset="utf-8";`, "body", "$hasnoattachment"},
		{"trailing disposition separator", "Content-Disposition: inline;", "body", "$hasnoattachment"},
		{"trailing separator and comment", "Content-Type: text/plain; (end)", "body", "$hasnoattachment"},
		{"trailing multipart separator", "Content-Type: multipart/mixed; boundary=b;", "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n--b--\r\n", "$hasnoattachment"},
		{"comment after attachment type", "Content-Disposition: attachment (PDF)", "PDF", "$hasattachment"},
		{"comment before disposition type", "Content-Disposition: (PDF) attachment", "PDF", "$hasattachment"},
		{"comment after filename", `Content-Disposition: inline; filename="report.pdf" (PDF)`, "PDF", "$hasattachment"},
		{"comment before filename", `Content-Disposition: inline; size=123 (bytes); filename="report.pdf"`, "PDF", "$hasattachment"},
		{"comments between disposition tokens", `Content-Disposition: inline; (file) filename (name) = (value) "report.pdf"`, "PDF", "$hasattachment"},
		{"comment does not invent filename", `Content-Disposition: inline; size=123 (notes; filename=report.pdf; more)`, "body", "$hasnoattachment"},
		{"nested disposition comments", `Content-Disposition: inline (outer (notes; filename=report.pdf) tail)`, "body", "$hasnoattachment"},
		{"quotes inside disposition comment", `Content-Disposition: inline (notes "abc; filename=report.pdf; "more);`, "body", "$hasnoattachment"},
		{"quoted literal parentheses remain filename", `Content-Disposition: inline; filename="report (final).pdf"`, "PDF", "$hasattachment"},
		{"quoted semicolon remains filename", `Content-Disposition: inline; filename="report;.pdf";`, "PDF", "$hasattachment"},
		{"unclosed disposition comment stays unknown", `Content-Disposition: inline (notes; filename=report.pdf`, "body", ""},
		{"unclosed comment after separator stays unknown", `Content-Type: text/plain; (notes; name=report.pdf`, "body", ""},
		{"interior empty parameter stays unknown", `Content-Type: text/plain;;`, "body", ""},
		{"malformed parameter stays unknown", `Content-Type: text/plain; badparam;`, "body", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyword, known := AttachmentKeyword([]byte(tc.headers + "\r\n\r\n" + tc.body))
			if string(keyword) != tc.want || known != (tc.want != "") {
				t.Fatalf("got %q, %v; want %q", keyword, known, tc.want)
			}
		})
	}
}
