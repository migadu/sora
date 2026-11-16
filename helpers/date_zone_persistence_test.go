package helpers

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
)

func TestAttachedDateExplicitZoneSurvivesGobWithLocalUTC(t *testing.T) {
	// Fixed zero-offset times can decode into time.UTC when Local is UTC.
	// Isolate that process-wide application setting from all other tests.
	const childEnv = "SORA_TEST_ATTACHED_DATE_EXPLICIT_ZONE_LOCAL_UTC"
	if os.Getenv(childEnv) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAttachedDateExplicitZoneSurvivesGobWithLocalUTC$", "-test.count=1", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated attached date persistence checks failed: %v\n%s", err, output)
		}
		return
	}
	time.Local = time.UTC

	const known = "Tue, 01 Jan 2019 12:00:00 +0000"
	const unknown = "Wed, 02 Jan 2019 13:00:00 GMT+1"
	const knownNested = "Thu, 03 Jan 2019 14:00:00 GMT"
	message := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\nContent-Type: message/rfc822\r\n\r\n" +
		"Date: " + known + "\r\nSubject: known parent\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n" +
		"--inner\r\nContent-Type: message/global\r\n\r\n" +
		"Date: " + unknown + "\r\nSubject: unknown child\r\nContent-Type: text/plain\r\n\r\nunknown\r\n" +
		"--inner\r\nContent-Type: message/rfc822\r\n\r\n" +
		"Date: " + knownNested + "\r\nSubject: known child\r\nContent-Type: text/plain\r\n\r\nknown\r\n" +
		"--inner--\r\n--outer--\r\n"
	bs, err := SafeBodyStructure([]byte(message))
	if err != nil {
		t.Fatal(err)
	}
	data, err := SerializeBodyStructureGob(&bs)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := DeserializeBodyStructureGob(data)
	if err != nil {
		t.Fatal(err)
	}
	for label, body := range map[string]imap.BodyStructure{"extracted": bs, "stored": *stored} {
		t.Run(label, func(t *testing.T) {
			var envelopes []*imap.Envelope
			var collect func(imap.BodyStructure)
			collect = func(part imap.BodyStructure) {
				switch part := part.(type) {
				case *imap.BodyStructureMultiPart:
					for _, child := range part.Children {
						collect(child)
					}
				case *imap.BodyStructureSinglePart:
					if part.MessageRFC822 != nil {
						envelopes = append(envelopes, part.MessageRFC822.Envelope)
						collect(part.MessageRFC822.BodyStructure)
					}
				}
			}
			collect(body)
			if len(envelopes) != 3 {
				t.Fatalf("got %d attached envelopes, want 3", len(envelopes))
			}
			for i, want := range []struct {
				subject string
				time    time.Time
				unknown bool
			}{
				{"known parent", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC), false},
				{"unknown child", time.Date(2019, 1, 2, 13, 0, 0, 0, time.UTC), true},
				{"known child", time.Date(2019, 1, 3, 14, 0, 0, 0, time.UTC), false},
			} {
				got := envelopes[i]
				if got == nil || got.Subject != want.subject || !got.Date.Equal(want.time) || got.DateUnknownZone != want.unknown {
					t.Errorf("envelope %d = %+v, want subject=%q date=%v unknown=%t", i, got, want.subject, want.time, want.unknown)
				}
			}
		})
	}

	for _, value := range []string{known, knownNested, strings.Replace(known, "+0000", "UT", 1)} {
		t.Run(value, func(t *testing.T) {
			knownBS, err := SafeBodyStructure([]byte(attachedMessage(value)))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := SerializeBodyStructureGob(&knownBS)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DeserializeBodyStructureGob(encoded)
			if err != nil {
				t.Fatal(err)
			}
			part := (*decoded).(*imap.BodyStructureMultiPart).Children[1].(*imap.BodyStructureSinglePart)
			if part.MessageRFC822.Envelope.DateUnknownZone {
				t.Fatalf("known zero-offset date gained unknown-zone metadata after gob: %+v", part.MessageRFC822.Envelope)
			}
		})
	}
}
