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
		date    string
		offset  int // seconds east of UTC; the wall time is always 1996-07-17 02:23:25
		unknown bool
	}{
		{"Wed, 17 Jul 1996 02:23:25 PDT", -7 * h, false},
		{"Wed, 17 Jul 1996 02:23:25 EST", -5 * h, false},
		{"Wed, 17 Jul 1996 02:23:25 pdt", -7 * h, false},
		{"Wed, 17 Jul 1996 02:23:25\r\n\tPdT", -7 * h, false},
		{"Wed, 17 Jul 1996 02:23:25 Z", 0, true},
		{"Wed, 17 Jul 1996 02:23:25 CEST", 0, true},
		{"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)", -7 * h, false},
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
			assert.Equal(t, tc.unknown, part.MessageRFC822.Envelope.DateUnknownZone, "TZ=%s %q: explicit source zone", name, tc.date)
		}
	}
}

// TestSafeBodyStructureAttachedMessageUnknownZone: the envelope of an attached message
// whose Date: zone is malformed or not defined keeps the date and time as written, in UTC,
// with explicit unknown-zone metadata that go-imap writes as "-0000" (RFC 5256 section 2.2: "If
// the time zone is invalid, the date and time SHOULD be treated as UTC"), and keeps that
// zone through the gob encoding the body structure is stored in. A known zone of offset
// zero stays "+0000" through it.
func TestSafeBodyStructureAttachedMessageUnknownZone(t *testing.T) {
	attachedEnvelope := func(t *testing.T, bs imap.BodyStructure) *imap.Envelope {
		t.Helper()
		mp, ok := bs.(*imap.BodyStructureMultiPart)
		require.True(t, ok, "body structure %#v", bs)
		require.Len(t, mp.Children, 2)
		part, ok := mp.Children[1].(*imap.BodyStructureSinglePart)
		require.True(t, ok && part.MessageRFC822 != nil, "part 2 %#v", mp.Children[1])
		return part.MessageRFC822.Envelope
	}
	wall := time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)
	for _, tc := range []struct {
		date    string
		unknown bool
	}{
		{"Wed, 17 Jul 1996 02:23:25 GMT+1", true},
		{"Wed, 17 Jul 1996 02:23:25 PDT+0400", true},
		{"Wed, 17 Jul 1996 02:23:25 +01", true},
		{"Wed, 17 Jul 1996 02:23:25 CET/CEST", true},
		{"Wed, 17 Jul 1996 02:23:25 Z", true},
		{"Wed, 17 Jul 1996 02:23:25 -0000", true},
		{"Wed, 17 Jul 1996 02:23:25 +0000", false},
		{"Wed, 17 Jul 1996 02:23:25 GMT", false},
	} {
		bs, err := SafeBodyStructure([]byte(attachedMessage(tc.date)))
		require.NoError(t, err)
		data, err := SerializeBodyStructureGob(&bs)
		require.NoError(t, err)
		stored, err := DeserializeBodyStructureGob(data)
		require.NoError(t, err)

		for _, got := range []struct {
			name     string
			envelope *imap.Envelope
		}{{"extracted", attachedEnvelope(t, bs)}, {"stored", attachedEnvelope(t, *stored)}} {
			assert.True(t, got.envelope.Date.Equal(wall), "%q: %s attached envelope date %v, want %v", tc.date, got.name, got.envelope.Date, wall)
			assert.Equal(t, tc.unknown, got.envelope.DateUnknownZone,
				"%q: %s attached envelope date %v: unknown zone = %v, want %v", tc.date, got.name, got.envelope.Date, got.envelope.DateUnknownZone, tc.unknown)
		}
	}
}
