package helpers

import (
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// attachedMessage is a message forwarding, as message/rfc822, one with the given Date.
func attachedMessage(date string) string {
	return "From: alice@example.com\r\nDate: Thu, 18 Jul 1996 00:00:00 +0000\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		"--b\r\nContent-Type: message/rfc822\r\n\r\n" +
		"From: bob@example.org\r\nDate: " + date + "\r\nSubject: attached\r\n\r\nbody\r\n" +
		"--b--\r\n"
}

// TestSafeBodyStructureAttachedMessageObsoleteZone: the envelope of an attached
// message/rfc822 part, stored in the BODYSTRUCTURE, reads an alphabetic Date: zone as
// ParseDateHeader does (RFC 5322 section 4.3), in whatever zone the host runs. The
// go-imap extractor used net/mail, so PDT was +0000 on a host in UTC, EST in July -0400
// on one in America/New_York, and a lower-case or military zone gave NIL.
func TestSafeBodyStructureAttachedMessageObsoleteZone(t *testing.T) {
	const h = 3600
	cases := []struct {
		date   string
		offset int // seconds east of UTC; the wall time is always 1996-07-17 02:23:25
	}{
		{"Wed, 17 Jul 1996 02:23:25 PDT", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 EST", -5 * h},
		{"Wed, 17 Jul 1996 02:23:25 pdt", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25\r\n\tPdT", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 Z", 0},
		{"Wed, 17 Jul 1996 02:23:25 CEST", 0},
		{"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)", -7 * h},
	}

	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	for _, name := range []string{"UTC", "America/Los_Angeles", "America/New_York", "Europe/Berlin"} {
		loc, err := time.LoadLocation(name)
		require.NoError(t, err)
		time.Local = loc // no test in this package runs in parallel
		for _, tc := range cases {
			bs, err := SafeBodyStructure([]byte(attachedMessage(tc.date)))
			require.NoError(t, err)
			mp, ok := bs.(*imap.BodyStructureMultiPart)
			require.True(t, ok, "body structure %#v", bs)
			require.Len(t, mp.Children, 2)
			part, ok := mp.Children[1].(*imap.BodyStructureSinglePart)
			require.True(t, ok && part.MessageRFC822 != nil, "part 2 %#v", mp.Children[1])

			got := part.MessageRFC822.Envelope.Date
			want := time.Date(1996, 7, 17, 2, 23, 25, 0, time.FixedZone("", tc.offset))
			_, offset := got.Zone()
			assert.True(t, want.Equal(got), "TZ=%s %q: attached envelope date %v, want %v", name, tc.date, got, want)
			assert.Equal(t, tc.offset, offset, "TZ=%s %q: zone offset of %v", name, tc.date, got)
		}
	}
}
