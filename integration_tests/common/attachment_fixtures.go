//go:build integration

package common

import "strings"

// AttachmentKeywordRegressionCases is shared by the real APPEND, LMTP, and
// delivery tests so each ingestion path exercises the same malformed MIME.
func AttachmentKeywordRegressionCases() []struct{ Name, MIME, Keyword string } {
	msg := func(lines ...string) string { return strings.Join(lines, "\r\n") + "\r\n" }
	return []struct{ Name, MIME, Keyword string }{
		{"attached multipart", msg(`Content-Type: multipart/related; boundary=b`,
			`Content-Disposition: attachment; filename="page.mhtml"`, "",
			"--b", "Content-Type: text/html", "", "<p>page</p>", "--b--"), "$hasattachment"},
		{"unquoted attachment filename", msg("Content-Type: application/pdf",
			"Content-Disposition: attachment; filename=quarterly report.pdf", "", "PDF"), "$hasattachment"},
		{"bad sibling before attachment", msg("Content-Type: multipart/mixed; boundary=b", "",
			"--b", "Content-Type: text/plain; charset=utf-8; badparam", "", "body",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"bad sibling after attachment", msg("Content-Type: multipart/mixed; boundary=b", "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF",
			"--b", "Content-Type: multipart/mixed; boundary=inner", "", "missing inner boundary", "--b--"), "$hasattachment"},
		{"bad nested sibling before attachment", msg("Content-Type: multipart/mixed; boundary=b", "",
			"--b", "Content-Type: multipart/mixed; boundary=inner", "", "missing inner boundary",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"truncated attachment multipart", msg("Content-Type: multipart/mixed; boundary=b", "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF"), "$hasattachment"},
		{"latin1 filename", msg("Content-Type: application/pdf",
			"Content-Disposition: inline; filename*=iso-8859-1''%E4%F6%FC.pdf", "", "PDF"), "$hasattachment"},
		{"windows filename", msg("Content-Type: application/pdf",
			"Content-Disposition: inline; filename*=windows-1252''%80.pdf", "", "PDF"), "$hasattachment"},
		{"unspecified filename charset", msg("Content-Type: application/pdf",
			"Content-Disposition: inline; filename*=''report%201.pdf", "", "PDF"), "$hasattachment"},
		{"continued latin1 filename", msg("Content-Type: application/pdf",
			"Content-Disposition: inline; filename*1*=.pdf; filename*0*=iso-8859-1''%E4", "", "PDF"), "$hasattachment"},
		{"latin1 name only", msg("Content-Type: application/pdf; name*=iso-8859-1''%E4.pdf", "", "PDF"), "$hasattachment"},
		{"latin1 multipart name", msg("Content-Type: multipart/mixed; boundary=b; name*=iso-8859-1''%E4.mime", "",
			"--b", "Content-Type: text/plain", "", "body", "--b--"), "$hasattachment"},
		{"latin1 related image stays inline", msg("Content-Type: multipart/related; boundary=b", "",
			"--b", "Content-Type: text/html", "", "<p>body</p>",
			"--b", "Content-Type: image/png", "Content-Disposition: inline; filename*=iso-8859-1''%E4.png", "", "PNG", "--b--"), "$hasnoattachment"},
		{"signature filename stays excluded", msg("Content-Type: application/pkcs7-signature; name*=iso-8859-1''%E4.p7s",
			"Content-Disposition: attachment; filename=broken filename.p7s", "", "signature"), "$hasnoattachment"},
		{"unmatched boundary stays unknown", msg("Content-Type: multipart/mixed; boundary=declared", "",
			"--actual", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--actual--"), ""},
		{"truncated plain multipart stays unknown", msg("Content-Type: multipart/mixed; boundary=b", "",
			"--b", "Content-Type: text/plain", "", "body"), ""},
	}
}
