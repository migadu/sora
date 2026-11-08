package helpers

import (
	"fmt"
	"strings"
	"testing"
)

// Fixed-width unique boundaries cannot be prefixes of any ancestor delimiter.
// Comments exercise valid MIME that the earlier BODYSTRUCTURE parser leaves
// shallow, so this isolates the extra classifier work from existing parsers.
func nestedAttachmentMIME(depth int, leaf string) string {
	var raw strings.Builder
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&raw, "Content-Type: multipart/mixed (nested); boundary=n%08d\r\n\r\n--n%08d\r\n", i, i)
	}
	raw.WriteString(leaf)
	for i := depth - 1; i >= 0; i-- {
		fmt.Fprintf(&raw, "\r\n--n%08d--\r\n", i)
	}
	return raw.String()
}

func TestAttachmentKeyword_NestingBudget(t *testing.T) {
	const plain = "Content-Type: text/plain\r\n\r\nbody"
	const attached = "Content-Type: application/pdf\r\nContent-Disposition: attachment\r\n\r\nPDF"
	for _, tc := range []struct {
		name, leaf, want string
		depth            int
	}{
		{"ordinary", plain, "$hasnoattachment", 4},
		{"at limit", plain, "$hasnoattachment", 128},
		{"attachment at limit", attached, "$hasattachment", 128},
		{"one level over", plain, "", 129},
		{"hidden attachment over limit", attached, "", 129},
		{"far over limit", plain, "", 256},
		{"large deep input", plain, "", 20000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(nestedAttachmentMIME(tc.depth, tc.leaf))
			keyword, known := AttachmentKeyword(data)
			if string(keyword) != tc.want || known != (tc.want != "") {
				t.Fatalf("got %q, %v at depth %d; want %q", keyword, known, tc.depth, tc.want)
			}
		})
	}

	t.Run("multipart disposition settles before descent", func(t *testing.T) {
		raw := "Content-Disposition: attachment\r\n" + nestedAttachmentMIME(256, plain)
		if keyword, known := AttachmentKeyword([]byte(raw)); !known || keyword != KeywordHasAttachment {
			t.Fatalf("known multipart attachment = %q, %v", keyword, known)
		}
	})
	t.Run("budget limits active depth across siblings", func(t *testing.T) {
		raw := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n" +
			nestedAttachmentMIME(127, plain) + "\r\n--outer\r\n" +
			nestedAttachmentMIME(127, plain) + "\r\n--outer--\r\n"
		if keyword, known := AttachmentKeyword([]byte(raw)); !known || keyword != KeywordHasNoAttachment {
			t.Fatalf("shallow siblings = %q, %v; want no attachments", keyword, known)
		}
	})
	for _, first := range []bool{true, false} {
		t.Run(fmt.Sprintf("visible attachment first=%v", first), func(t *testing.T) {
			firstPart, secondPart := attached, nestedAttachmentMIME(256, plain)
			want := "$hasattachment"
			if !first {
				firstPart, secondPart = secondPart, firstPart
				want = "" // Work stops before the later sibling can be inspected.
			}
			raw := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n" + firstPart +
				"\r\n--outer\r\n" + secondPart + "\r\n--outer--\r\n"
			if keyword, known := AttachmentKeyword([]byte(raw)); string(keyword) != want || known != (want != "") {
				t.Fatalf("got %q, %v; want %q", keyword, known, want)
			}
		})
	}
}

func BenchmarkAttachmentKeywordDeepMultipart(b *testing.B) {
	for _, depth := range []int{128, 1000, 10000, 20000} {
		b.Run(fmt.Sprint(depth), func(b *testing.B) {
			raw := []byte(nestedAttachmentMIME(depth, "Content-Type: text/plain\r\n\r\nbody"))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = AttachmentKeyword(raw)
			}
		})
	}
}
