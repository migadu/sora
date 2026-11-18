package imaptest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// coreReplyClient responds to one command over a real byte stream, so these
// tests verify the semantic assertions against legal server response variants.
func coreReplyClient(t *testing.T, replies string) *Client {
	t.Helper()
	local, remote := net.Pipe()
	c := &Client{conn: local, reader: bufio.NewReader(local), ctx: context.Background(), cfg: Config{CommandTimeout: time.Second}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer remote.Close()
		line, err := bufio.NewReader(remote).ReadString('\n')
		if err != nil {
			return
		}
		tag, _, _ := strings.Cut(line, " ")
		fmt.Fprintf(remote, "%s%s OK complete\r\n", replies, tag)
	}()
	t.Cleanup(func() {
		_ = c.Close()
		_ = remote.Close()
		<-done
	})
	return c
}

func TestCoreFetchMergesSplitItemsAndIgnoresOtherMessages(t *testing.T) {
	c := coreReplyClient(t, "* 2 FETCH (FLAGS (\\Seen))\r\n"+
		"* 1 FETCH (UID 912)\r\n"+
		"* 1 FETCH (BODY[] {5}\r\nhello)\r\n"+
		"* 1 FETCH (FLAGS ())\r\n")
	f, err := coreSingleFetch(c, "FETCH 1 (UID BODY.PEEK[])")
	if err != nil {
		t.Fatal(err)
	}
	if f.Seq != 1 || f.Attrs["UID"].Text != "912" || f.Attrs["BODY[]"].Text != "hello" {
		t.Fatalf("did not merge requested FETCH data: %#v", f)
	}
}

func TestCoreUIDsAcceptsSparseAllocationAndUnsolicitedFlags(t *testing.T) {
	c := coreReplyClient(t, "* 3 FETCH (FLAGS (\\Flagged))\r\n"+
		"* 2 FETCH (UID 9001)\r\n"+
		"* 1 FETCH (UID 37)\r\n"+
		"* 1 FETCH (FLAGS ())\r\n")
	uids, err := coreUIDs(c)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(uids, []uint64{37, 9001}) {
		t.Fatalf("UIDs=%v, want captured sparse UID allocation", uids)
	}
}

func TestCoreUIDsRejectsInvalidOrdering(t *testing.T) {
	c := coreReplyClient(t, "* 1 FETCH (UID 9001)\r\n* 2 FETCH (UID 37)\r\n")
	if _, err := coreUIDs(c); err == nil {
		t.Fatal("accepted decreasing UIDs across increasing sequence numbers")
	}
}

func TestCoreUIDPersistenceHonorsUIDValidity(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		beforeValidity, afterValidity uint64
		before, after                 []uint64
		wantError                     bool
	}{
		{"persistent", 7, 7, []uint64{3, 9}, []uint64{3, 9}, false},
		{"new-generation", 7, 8, []uint64{3, 9}, []uint64{1, 2}, false},
		{"unchanged-validity", 7, 7, []uint64{3, 9}, []uint64{1, 2}, true},
		{"decreased-validity", 7, 6, []uint64{3, 9}, []uint64{1, 2}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := coreCheckUIDPersistence(tc.beforeValidity, tc.afterValidity, tc.before, tc.after)
			if (err != nil) != tc.wantError {
				t.Fatalf("UID persistence assertion=%v, want error=%t", err, tc.wantError)
			}
		})
	}
}

func TestCoreBodyFetchRequiresRequestedData(t *testing.T) {
	if err := coreCheckBody(Fetch{Seq: 1, Attrs: map[string]Value{"FLAGS": {IsList: true}}}, []byte("body")); err == nil {
		t.Fatal("FLAGS-only reply satisfied a BODY[] request")
	}
	if err := coreCheckBody(Fetch{Seq: 1, Attrs: map[string]Value{"BODY[]": {Text: "body", IsLiteral: true}}}, []byte("body")); err != nil {
		t.Fatal(err)
	}
}
