//go:build integration

package common

import (
	"fmt"
	"strings"
)

// AttachmentKeywordRegressionCases is shared by the real APPEND, LMTP, and
// delivery tests so each ingestion path exercises the same malformed MIME.
func AttachmentKeywordRegressionCases() []struct{ Name, MIME, Keyword string } {
	msg := func(lines ...string) string { return strings.Join(lines, "\r\n") + "\r\n" }
	return []struct{ Name, MIME, Keyword string }{
		{"over nested plain remains unknown", NestedAttachmentMIME(256, false), ""},
		{"over nested hidden attachment remains unknown", NestedAttachmentMIME(256, true), ""},
		{"shallow nested plain", NestedAttachmentMIME(4, false), "$hasnoattachment"},
		{"shallow nested attachment", NestedAttachmentMIME(4, true), "$hasattachment"},
		{"attachment before over nested sibling", msg("Content-Type: multipart/mixed; boundary=known-outer", "",
			"--known-outer", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF",
			"--known-outer", NestedAttachmentMIME(256, false), "--known-outer--"), "$hasattachment"},
		{"UTF16BE boundary decodes to b", msg("Content-Type: multipart/mixed; boundary*=utf-16be''%00%62", "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"UTF16LE boundary decodes to b", msg("Content-Type: multipart/mixed; boundary*=utf-16le''%62%00", "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"continued UTF16 boundary joins code unit", msg("Content-Type: multipart/mixed; boundary*0*=utf-16be''%00; boundary*1*=%62", "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"continued ISO2022 boundary joins escape", msg("Content-Type: multipart/mixed; boundary*0*=iso-2022-jp''%1B%24; boundary*1*=%42%1B%28%42b", "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"continued ISO2022 boundary retains shift state", msg("Content-Type: multipart/mixed; boundary*0*=iso-2022-jp''%1B%24%42; boundary*1*=bb", "",
			"--bb", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--bb--"), ""},
		{"ISO2022 state only filename is empty", msg("Content-Type: application/pdf",
			"Content-Disposition: inline; filename*=iso-2022-jp''%1B%28%42", "", "PDF"), "$hasnoattachment"},
		{"UTF16 BOM only filename is empty", msg("Content-Type: application/pdf",
			"Content-Disposition: inline; filename*=utf-16''%FE%FF", "", "PDF"), "$hasnoattachment"},
		{"unknown charset filename stays unknown", msg("Content-Type: application/pdf",
			"Content-Disposition: inline; filename*=x-sora-unknown''report.pdf", "", "PDF"), ""},
		{"legacy filename survives unknown charset alternative", msg("Content-Type: application/pdf",
			`Content-Disposition: inline; filename="report.pdf"; filename*=x-sora-unknown''report.pdf`, "", "PDF"), "$hasattachment"},
		{"explicit attachment survives unknown charset name", msg("Content-Type: application/pdf; name*=x-sora-unknown''report.pdf",
			"Content-Disposition: attachment", "", "PDF"), "$hasattachment"},
		{"trailing charset semicolon", msg(`Content-Type: text/plain; charset="utf-8";`, "", "body"), "$hasnoattachment"},
		{"trailing inline semicolon", msg("Content-Type: text/plain", "Content-Disposition: inline;", "", "body"), "$hasnoattachment"},
		{"trailing multipart semicolon", msg("Content-Type: multipart/mixed; boundary=b;", "",
			"--b", "Content-Type: text/plain", "", "body", "--b--"), "$hasnoattachment"},
		{"commented attachment disposition", msg("Content-Type: application/pdf", `Content-Disposition: attachment (PDF); filename="report.pdf"`, "", "PDF"), "$hasattachment"},
		{"comment before inline filename", msg("Content-Type: application/pdf", `Content-Disposition: inline; size=123 (bytes); filename="report.pdf"`, "", "PDF"), "$hasattachment"},
		{"comment after inline filename", msg("Content-Type: application/pdf", `Content-Disposition: inline; filename="report.pdf" (PDF)`, "", "PDF"), "$hasattachment"},
		{"disposition comment cannot supply filename", msg("Content-Type: text/plain", `Content-Disposition: inline; size=123 (notes; filename=report.pdf; bytes)`, "", "body"), "$hasnoattachment"},
		{"duplicate content types stay unknown", msg("Content-Type: text/plain", "Content-Type: multipart/mixed; boundary=b", "",
			"--b", "Content-Disposition: attachment", "", "PDF", "--b--"), ""},
		{"duplicate dispositions stay unknown", msg("Content-Type: application/pdf", "Content-Disposition: inline", "Content-Disposition: attachment", "", "PDF"), ""},
		{"related boundary survives unquoted type", msg(`Content-Type: multipart/related; boundary="b"; type=text/html`, "",
			"--b", "Content-Type: text/html", "", "<p>body</p>",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"boundary after unquoted type", msg(`Content-Type: multipart/related; type=text/html; boundary="b"`, "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"signed boundary survives unquoted protocol", msg(`Content-Type: multipart/signed; boundary="b"; protocol=application/pgp-signature; micalg=pgp-sha256`, "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"boundary survives trailing bad parameter", msg(`Content-Type: multipart/mixed; boundary="b"; badparam`, "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"valid extended after bad legacy", msg("Content-Type: application/pdf",
			"Content-Disposition: inline; filename=quarterly report.pdf; filename*=UTF-8''quarterly%20report.pdf", "", "PDF"), "$hasattachment"},
		{"valid legacy before bad extended", msg("Content-Type: application/pdf",
			`Content-Disposition: inline; filename="quarterly report.pdf"; filename*=UTF-8''quarterly report.pdf`, "", "PDF"), "$hasattachment"},
		{"valid extended name after bad legacy", msg("Content-Type: application/pdf; name=quarterly report.pdf; name*=UTF-8''quarterly%20report.pdf", "", "PDF"), "$hasattachment"},
		{"unclosed quote does not create filename", msg("Content-Type: application/pdf",
			`Content-Disposition: inline; x="unclosed; description="notes; filename=report.pdf`, "", "body"), ""},
		{"stray quote does not create filename", msg("Content-Type: application/pdf",
			`Content-Disposition: inline; x=foo"bar; description="notes; filename=report.pdf; y="`, "", "body"), ""},
		{"digest omitted child type", msg("Content-Type: multipart/digest; boundary=b", "",
			"--b", "", "From: sender@example.com", "Subject: forwarded", "", "body", "--b--"), "$hasattachment"},
		{"digest explicit plain child", msg("Content-Type: multipart/digest; boundary=b", "",
			"--b", "Content-Type: text/plain", "", "body", "--b--"), "$hasnoattachment"},
		{"comment containing a false filename", msg("Content-Type: text/plain; charset=us-ascii (notes; name=report.pdf; more)", "", "body"), "$hasnoattachment"},
		{"comment after boundary", msg("Content-Type: multipart/mixed; boundary=b (notes)", "",
			"--b", "Content-Type: application/pdf", "Content-Disposition: attachment", "", "PDF", "--b--"), "$hasattachment"},
		{"unknown disposition is attachment", msg("Content-Type: text/plain", "Content-Disposition: x-custom", "", "body"), "$hasattachment"},
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

// NestedAttachmentMIME builds valid MIME with unique fixed-width boundaries.
// Comments exercise the raw classifier independently of the BODYSTRUCTURE
// extractor's permissive fallback for MIME syntax it does not understand.
func NestedAttachmentMIME(depth int, attached bool) string {
	var raw strings.Builder
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&raw, "Content-Type: multipart/mixed (nested); boundary=nest%04d\r\n\r\n--nest%04d\r\n", i, i)
	}
	if attached {
		raw.WriteString("Content-Type: application/pdf\r\nContent-Disposition: attachment\r\n\r\nPDF")
	} else {
		raw.WriteString("Content-Type: text/plain\r\n\r\nbody")
	}
	for i := depth - 1; i >= 0; i-- {
		fmt.Fprintf(&raw, "\r\n--nest%04d--\r\n", i)
	}
	return raw.String()
}
