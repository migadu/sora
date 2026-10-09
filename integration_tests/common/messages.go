//go:build integration

package common

import (
	"bytes"
	"encoding/base64"
	"strings"
)

// MultipartWithPDF returns the shape most real mail with an attachment has: a
// multipart/mixed message holding a multipart/alternative text+HTML body, whose text
// part carries bodyText, and a base64 application/pdf attachment of pdfSize octets
// before encoding. Lines end in CRLF.
func MultipartWithPDF(to, subject, bodyText string, pdfSize int) string {
	encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'%'}, pdfSize))
	var pdf strings.Builder
	for len(encoded) > 76 {
		pdf.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	pdf.WriteString(encoded + "\r\n")

	return strings.Join([]string{
		"From: sender@example.com",
		"To: " + to,
		"Subject: " + subject,
		"Message-ID: <" + subject + "@example.com>",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="mixed"`,
		"",
		"--mixed",
		`Content-Type: multipart/alternative; boundary="alt"`,
		"",
		"--alt",
		"Content-Type: text/plain; charset=utf-8",
		"",
		bodyText,
		"--alt",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>" + bodyText + "</p>",
		"--alt--",
		"--mixed",
		`Content-Type: application/pdf; name="invoice.pdf"`,
		`Content-Disposition: attachment; filename="invoice.pdf"`,
		"Content-Transfer-Encoding: base64",
		"",
		pdf.String() + "--mixed--",
		"",
	}, "\r\n")
}

// SieveRawMessageCase is one delivery whose filing depends on the Sieve body or size
// test seeing the message as it is stored: Sieve used to be handed the extracted
// search text instead, which has no MIME structure and is far smaller than the message.
type SieveRawMessageCase struct {
	Name    string
	Script  string
	Message func(to, subject string) string
	Mailbox string // where the delivery must land; "" means nowhere (discarded)
}

// SieveRawMessageCases is shared by every ingress path, so LMTP and Admin API delivery
// are held to the same outcome for the same script and message. The PDF is ~150 KB, so
// the message is over 100K and well under 1M.
//
// Case names become test account local parts: no colons or other characters an
// email address cannot carry.
func SieveRawMessageCases() []SieveRawMessageCase {
	invoice := func(to, subject string) string {
		return MultipartWithPDF(to, subject, "invoice 4711 attached", 150*1024)
	}
	return []SieveRawMessageCase{
		{
			Name:    "body text of a multipart message",
			Script:  `require ["body", "fileinto"]; if body :contains "invoice 4711" { fileinto "Archive"; }`,
			Message: invoice,
			Mailbox: "Archive",
		},
		{
			Name:    "body text absent from a multipart message",
			Script:  `require ["body", "fileinto"]; if body :contains "invoice 4712" { fileinto "Archive"; }`,
			Message: invoice,
			Mailbox: "INBOX",
		},
		{
			Name:    "body content type of an attachment",
			Script:  `require ["body", "fileinto"]; if body :content "application/pdf" :contains "" { fileinto "Archive"; }`,
			Message: invoice,
			Mailbox: "Archive",
		},
		{
			// RFC 5429 reject is delivered as a discard, with no bounce; the rest of
			// the script compiles and runs (a script requiring reject used to fail whole).
			Name:    "reject discards without a bounce",
			Script:  `require ["fileinto", "reject"]; if size :over 100K { reject "too big"; stop; } fileinto "Archive";`,
			Message: invoice,
			Mailbox: "",
		},
		{
			Name:    "size counts the attachment",
			Script:  `require ["fileinto"]; if size :over 100K { fileinto "Archive"; }`,
			Message: invoice,
			Mailbox: "Archive",
		},
		{
			Name:    "size is not inflated",
			Script:  `require ["fileinto"]; if size :over 1M { fileinto "Archive"; }`,
			Message: invoice,
			Mailbox: "INBOX",
		},
		{
			// Bulk mail's shape, and the one whose text no longer comes from
			// helpers.ExtractPlaintextBody: go-sieve decodes the transfer encoding and
			// charset and strips the tags itself.
			Name:   "body text of an HTML-only quoted-printable message",
			Script: `require ["body", "fileinto"]; if body :contains "Rechnung Nr. 4711 für Sie" { fileinto "Archive"; }`,
			Message: func(to, subject string) string {
				return QuotedPrintableHTMLMessage(to, subject, "<p>Rechnung&nbsp;Nr=2E 4711 f=C3=BCr Sie</p>")
			},
			Mailbox: "Archive",
		},
		{
			// RFC 5703: the shape attachment filters take, and what Dovecot
			// migrations bring along (`require "mime"` used to fail to
			// compile, which skipped the user's whole script).
			Name:    "attachment content type via header mime anychild",
			Script:  `require ["mime", "fileinto"]; if header :mime :anychild :contenttype "Content-Type" "application/pdf" { fileinto "Archive"; }`,
			Message: invoice,
			Mailbox: "Archive",
		},
		{
			Name:    "attachment filename via foreverypart",
			Script:  `require ["mime", "foreverypart", "fileinto"]; foreverypart { if header :mime :param "filename" :matches "Content-Disposition" "*.pdf" { fileinto "Archive"; break; } }`,
			Message: invoice,
			Mailbox: "Archive",
		},
		{
			Name:    "attachment presence via exists mime anychild",
			Script:  `require ["mime", "fileinto"]; if exists :mime :anychild "Content-Disposition" { fileinto "Archive"; }`,
			Message: invoice,
			Mailbox: "Archive",
		},
		{
			// extracttext is the one extension with a require dependency (variables
			// and foreverypart), and the body of the first leaf is what it extracts.
			Name:    "body text via extracttext in foreverypart",
			Script:  `require ["foreverypart", "extracttext", "variables", "fileinto"]; foreverypart { extracttext :first 100 "t"; if string :contains "${t}" "invoice 4711" { fileinto "Archive"; break; } }`,
			Message: invoice,
			Mailbox: "Archive",
		},
		{
			Name:    "attachment filename absent via foreverypart",
			Script:  `require ["mime", "foreverypart", "fileinto"]; foreverypart { if header :mime :param "filename" :matches "Content-Disposition" "*.exe" { fileinto "Archive"; break; } }`,
			Message: invoice,
			Mailbox: "INBOX",
		},
		{
			Name:   "body text of a base64 single-part message",
			Script: `require ["body", "fileinto"]; if body :contains "hello world" { fileinto "Archive"; }`,
			Message: func(to, subject string) string {
				return Base64TextMessage(to, subject, "hello world")
			},
			Mailbox: "Archive",
		},
	}
}

// QuotedPrintableHTMLMessage returns a single-part text/html message. html is the
// body already quoted-printable encoded. Lines end in CRLF.
func QuotedPrintableHTMLMessage(to, subject, html string) string {
	return strings.Join([]string{
		"From: sender@example.com",
		"To: " + to,
		"Subject: " + subject,
		"Message-ID: <" + subject + "@example.com>",
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"<html><body>" + html + "</body></html>",
		"",
	}, "\r\n")
}

// Base64TextMessage returns a single-part text/plain message whose body is
// base64-encoded, as some mailers send non-ASCII text. Lines end in CRLF.
func Base64TextMessage(to, subject, bodyText string) string {
	return strings.Join([]string{
		"From: sender@example.com",
		"To: " + to,
		"Subject: " + subject,
		"Message-ID: <" + subject + "@example.com>",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
		base64.StdEncoding.EncodeToString([]byte(bodyText)),
		"",
	}, "\r\n")
}
