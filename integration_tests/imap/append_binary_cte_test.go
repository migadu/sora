//go:build integration

package imap_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 3516 §§4.4, 6: accepting a literal8 APPEND must preserve decoded
// octets while exposing a base-IMAP-compatible BODY/BODYSTRUCTURE pair.
func TestIMAP_AppendBinaryCTE(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.Login(account.Email, account.Password).Wait())

	// The octet-stream's line endings are binary data, including its final LF.
	payload := []byte{0, '-', 0xe4, '\n', '\r', '\n', '\n'}
	const top = "From: sender@example.com\r\nSubject: =?us-ascii?Q?binary_append?=\r\nMIME-Version: 1.0\r\n"
	const binaryHeader = "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"
	const outerPreamble = "outer preamble \t\r\n"
	const innerPreamble = "inner preamble \t\r\n"
	const innerEpilogue = "inner epilogue \t\r\n"
	const outerEpilogue = "outer epilogue \t\r\n"
	const sibling = "Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: quoted-printable\r\nX-Untouched: keep \t\r\n\r\nunchanged=20sibling\r\n"
	nested := []byte(top + "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" + outerPreamble +
		"--outer\r\n" + sibling + "--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n" +
		innerPreamble + "--inner\r\n" + binaryHeader)
	nested = append(nested, payload...)
	nested = append(nested, []byte("\r\n--inner--\r\n"+innerEpilogue+"--outer--\r\n"+outerEpilogue)...)
	latin1 := []byte{0xe4, 0, 0xf6, '\r', '\n'}

	for n, tc := range []struct {
		name    string
		raw     []byte
		part    []int
		payload []byte
	}{
		{"octet stream", append([]byte(top+binaryHeader), payload...), []int{1}, payload},
		{"nested multipart", nested, []int{2, 1}, payload},
		{"non UTF8 text", append([]byte(top+"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: binary\r\n\r\n"), latin1...), []int{1}, latin1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Give each message its own mailbox so the test also checks APPENDUID
			// independently of the order in which the subtests execute.
			box := fmt.Sprintf("BinaryCTE%d", n)
			require.NoError(t, c.Create(box, nil).Wait())
			uid := appendBinaryCTE(t, c, box, tc.raw)
			_, err := c.Select(box, nil).Wait()
			require.NoError(t, err)

			full := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{Peek: true})
			assert.Equal(t, -1, bytes.IndexByte(full, 0), "ordinary BODY[] cannot contain NUL")
			assert.Contains(t, string(full), "Subject: =?us-ascii?Q?binary_append?=\r\n", "MIME encoded headers must remain unchanged")
			body := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{Part: tc.part, Peek: true})
			assert.Equal(t, -1, bytes.IndexByte(body, 0), "ordinary BODY part cannot contain NUL")
			header := fetchBodySection(t, c, uid, &imap.FetchItemBodySection{Part: tc.part, Specifier: imap.PartSpecifierMIME, Peek: true})
			mh, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(header))).ReadMIMEHeader()
			require.NoError(t, err)
			encoding := strings.ToLower(strings.TrimSpace(mh.Get("Content-Transfer-Encoding")))
			assert.NotEqual(t, "binary", encoding, "BODY must advertise its transport-safe representation")
			assert.Equal(t, tc.payload, decodeBinaryAppendBody(t, encoding, body), "BODY's advertised CTE must recover original octets")

			messages, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
				RFC822Size:        true,
				BodyStructure:     &imap.FetchItemBodyStructure{Extended: true},
				BinarySection:     []*imap.FetchItemBinarySection{{Part: tc.part, Peek: true}},
				BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: tc.part}},
			}).Collect()
			require.NoError(t, err)
			require.Len(t, messages, 1)
			message := messages[0]
			assert.Equal(t, int64(len(full)), message.RFC822Size, "RFC822.SIZE must measure the ordinary representation")
			part := binaryAppendStructurePart(t, message.BodyStructure, tc.part)
			assert.Equal(t, encoding, strings.ToLower(part.Encoding), "MIME header and BODYSTRUCTURE must agree")
			assert.Equal(t, uint32(len(body)), part.Size, "BODYSTRUCTURE must measure encoded BODY octets")
			require.Len(t, message.BinarySection, 1)
			require.Len(t, message.BinarySectionSize, 1)
			assert.Equal(t, tc.payload, message.BinarySection[0].Bytes, "BINARY must preserve all decoded octets")
			assert.Equal(t, uint32(len(tc.payload)), message.BinarySectionSize[0].Size)

			bodyPartial := &imap.FetchItemBodySection{Part: tc.part, Peek: true, Partial: &imap.SectionPartial{Offset: 2, Size: 3}}
			assert.Equal(t, body[2:min(5, len(body))], fetchBodySection(t, c, uid, bodyPartial), "BODY partial offsets use encoded octets")
			binaryPartial := &imap.FetchItemBinarySection{Part: tc.part, Peek: true, Partial: &imap.SectionPartial{Offset: 1, Size: 3}}
			messages, err = c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{binaryPartial}}).Collect()
			require.NoError(t, err)
			require.Len(t, messages, 1)
			require.Len(t, messages[0].BinarySection, 1)
			assert.Equal(t, tc.payload[1:4], messages[0].BinarySection[0].Bytes, "BINARY partial offsets use decoded octets")
			require.NotNil(t, messages[0].BinarySection[0].Section.Partial)
			assert.Equal(t, int64(1), messages[0].BinarySection[0].Section.Partial.Offset)

			if tc.name == "nested multipart" {
				for _, untouched := range []string{outerPreamble, innerPreamble, innerEpilogue, outerEpilogue, sibling} {
					assert.Contains(t, string(full), untouched, "recoding a leaf must preserve unaffected MIME bytes")
				}
				assert.Equal(t, []byte("unchanged=20sibling"), fetchBodySection(t, c, uid, &imap.FetchItemBodySection{Part: []int{1}, Peek: true}))
			}
			if tc.name == "non UTF8 text" {
				assert.Equal(t, "text/plain; charset=iso-8859-1", mh.Get("Content-Type"), "CTE conversion must preserve the declared charset")
			}
		})
	}

	t.Run("safe literal8 remains byte identical", func(t *testing.T) {
		raw := []byte(top + "Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nsafe=20content\r\n")
		uid := appendBinaryCTE(t, c, "INBOX", raw)
		_, err := c.Select("INBOX", nil).Wait()
		require.NoError(t, err)
		assert.Equal(t, raw, fetchBodySection(t, c, uid, &imap.FetchItemBodySection{Peek: true}), "literal8 alone does not justify rewriting a safe message")
	})
}

func appendBinaryCTE(t *testing.T, c *imapclient.Client, box string, raw []byte) imap.UID {
	t.Helper()
	command := c.Append(box, int64(len(raw)), &imap.AppendOptions{Binary: true})
	_, err := command.Write(raw)
	require.NoError(t, err)
	require.NoError(t, command.Close())
	result, err := command.Wait()
	require.NoError(t, err)
	return result.UID
}

// Decode the advertised transfer encoding without interpreting a text charset.
// Charset conversion would conceal accidental changes to non-UTF8 body octets.
func decodeBinaryAppendBody(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var reader io.Reader = bytes.NewReader(body)
	switch encoding {
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, reader)
	case "quoted-printable":
		reader = quotedprintable.NewReader(reader)
	case "7bit", "8bit", "binary", "":
	default:
		t.Fatalf("unexpected BODY Content-Transfer-Encoding %q", encoding)
	}
	decoded, err := io.ReadAll(reader)
	require.NoError(t, err)
	return decoded
}

func binaryAppendStructurePart(t *testing.T, structure imap.BodyStructure, path []int) *imap.BodyStructureSinglePart {
	t.Helper()
	for len(path) > 0 {
		switch current := structure.(type) {
		case *imap.BodyStructureMultiPart:
			require.GreaterOrEqual(t, path[0], 1)
			require.LessOrEqual(t, path[0], len(current.Children))
			structure, path = current.Children[path[0]-1], path[1:]
		case *imap.BodyStructureSinglePart:
			require.Equal(t, []int{1}, path)
			return current
		default:
			t.Fatalf("unexpected BODYSTRUCTURE %T", structure)
		}
	}
	part, ok := structure.(*imap.BodyStructureSinglePart)
	require.True(t, ok, "expected a single MIME leaf, got %T", structure)
	return part
}
