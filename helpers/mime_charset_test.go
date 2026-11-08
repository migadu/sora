package helpers

import "testing"

func TestAttachmentKeyword_CharsetBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, params, want string }{
		{"UTF16 big endian", "boundary*=utf-16be''%00%62", "$hasattachment"},
		{"UTF16 little endian", "boundary*=utf-16le''%62%00", "$hasattachment"},
		{"UTF16 big endian BOM", "boundary*=utf-16''%FE%FF%00%62", "$hasattachment"},
		{"UTF16 little endian BOM", "boundary*=utf-16''%FF%FE%62%00", "$hasattachment"},
		{"UTF16 without BOM defaults big endian", "boundary*=utf-16''%00%62", "$hasattachment"},
		{"split UTF16 code unit", "boundary*0*=utf-16be''%00; boundary*1*=%62", "$hasattachment"},
		{"mixed encoded and plain UTF16", "boundary*0*=utf-16be''%00; boundary*1=b", "$hasattachment"},
		{"split UTF16 BOM", "boundary*0*=utf-16''%FE; boundary*1*=%FF%00%62", "$hasattachment"},
		{"split stateful escape", `boundary*0*=iso-2022-jp''%1B; boundary*1="(Bb"`, "$hasattachment"},
		{"case insensitive charset", "boundary*=UtF-16bE'en'%00%62", "$hasattachment"},
		{"unspecified charset", "boundary*=''b", "$hasattachment"},
		{"unknown charset", "boundary*=x-no-such-charset''b", ""},
		{"registered unsupported charset", "boundary*=utf-7''b", ""},
		{"invalid UTF16", "boundary*=utf-16be''%00", ""},
		{"split percent triplet is invalid", "boundary*0*=utf-8''%; boundary*1=62", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "Content-Type: multipart/mixed; " + tc.params + "\r\n\r\n" +
				"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment\r\n\r\nPDF\r\n--b--\r\n"
			keyword, known := AttachmentKeyword([]byte(raw))
			if string(keyword) != tc.want || known != (tc.want != "") {
				t.Fatalf("got %q, %v; want %q", keyword, known, tc.want)
			}
		})
	}
}

func TestAttachmentKeyword_CharsetFilenameSemantics(t *testing.T) {
	for _, tc := range []struct{ name, params, want string }{
		{"UTF16 little endian empty BOM", "filename*=utf-16''%FF%FE", "$hasnoattachment"},
		{"UTF16 big endian empty BOM", "filename*=utf-16''%FE%FF", "$hasnoattachment"},
		{"ISO2022 state only", "filename*=iso-2022-jp''%1B%28B", "$hasnoattachment"},
		{"continued ISO2022 state only", `filename*0*=iso-2022-jp''%1B; filename*1="(B"`, "$hasnoattachment"},
		{"UTF16 decoded filename", "filename*=utf-16be''%00%62", "$hasattachment"},
		{"UTF8 character split between sections", "filename*0*=utf-8''%E2; filename*1*=%82%AC.pdf", "$hasattachment"},
		{"valid UTF8 replacement character", "filename*=utf-8''%EF%BF%BD", "$hasattachment"},
		{"valid UTF16BE replacement character", "filename*=utf-16be''%FF%FD", "$hasattachment"},
		{"valid UTF16LE BOM and replacement character", "filename*=utf-16''%FF%FE%FD%FF", "$hasattachment"},
		{"valid UTF16 no BOM and replacement character", "filename*=utf-16''%FF%FD", "$hasattachment"},
		{"unknown charset", "filename*=x-no-such-charset''report.pdf", ""},
		{"registered unsupported charset", "filename*=utf-7''report.pdf", ""},
		{"legacy fallback survives unknown charset", `filename="report.pdf"; filename*=x-no-such-charset''report.pdf`, "$hasattachment"},
		{"continued unknown charset", "filename*0*=x-no-such-charset''report; filename*1=.pdf", ""},
		{"invalid ASCII", "filename*=us-ascii''%FF", ""},
		{"invalid UTF8", "filename*=utf-8''%FF", ""},
		{"odd UTF16", "filename*=utf-16be''%00", ""},
		{"unpaired UTF16 surrogate", "filename*=utf-16be''%D8%00", ""},
		{"truncated ISO2022 escape", "filename*=iso-2022-jp''%1B", ""},
		{"legacy survives invalid UTF16", `filename="report.pdf"; filename*=utf-16be''%00`, "$hasattachment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "Content-Type: application/pdf\r\nContent-Disposition: inline; " + tc.params + "\r\n\r\nPDF"
			keyword, known := AttachmentKeyword([]byte(raw))
			if string(keyword) != tc.want || known != (tc.want != "") {
				t.Fatalf("got %q, %v; want %q", keyword, known, tc.want)
			}
		})
	}
}
