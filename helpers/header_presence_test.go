package helpers

import (
	"github.com/emersion/go-message"
	"strings"
	"testing"
)

func TestHeaderPresenceKeepsEmptyInvalidAndGroupFields(t *testing.T) {
	for _, value := range []string{"", "undisclosed-recipients:;", "not an address", "A <a@example.org>"} {
		e, err := message.Read(strings.NewReader("fRoM: " + value + "\r\nTo: " + value + "\r\nCc: " + value + "\r\n\r\nbody"))
		if err != nil {
			t.Fatal(err)
		}
		mask := ExtractHeaderPresence(e.Header)
		for _, key := range []string{"from", "to", "cc"} {
			bit, _ := HeaderPresenceBit(key)
			if *mask&bit == 0 {
				t.Fatalf("lost %s=%q", key, value)
			}
		}
		bit, _ := HeaderPresenceBit("subject")
		if *mask&bit != 0 {
			t.Fatal("invented Subject")
		}
	}
}
