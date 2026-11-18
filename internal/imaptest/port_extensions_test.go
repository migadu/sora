package imaptest

import "testing"

func TestPortESearchAcceptsEquivalentSparseSetRepresentation(t *testing.T) {
	c := coreReplyClient(t, "* ESEARCH (TAG \"S000001\") UID COUNT 3 MIN 7 MAX 200 ALL 7,99,200\r\n")
	err := portCheckESearch(c, "UID SEARCH RETURN (ALL MIN MAX COUNT) ALL", true, map[string]uint64{"COUNT": 3, "MIN": 7, "MAX": 200}, []uint64{7, 99, 200})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPortESearchRejectsWrongCorrelatorAndEmptyExtrema(t *testing.T) {
	for _, reply := range []string{
		"* ESEARCH (TAG \"unrelated\") UID COUNT 0\r\n",
		"* ESEARCH (TAG \"S000001\") UID COUNT 0 MIN 1\r\n",
		"* ESEARCH (TAG \"S000001\") COUNT 0\r\n",
	} {
		c := coreReplyClient(t, reply)
		if err := portCheckESearch(c, "UID SEARCH RETURN (COUNT MIN) NOT ALL", true, map[string]uint64{"COUNT": 0}, nil, "MIN", "MAX", "ALL"); err == nil {
			t.Errorf("accepted invalid ESEARCH: %q", reply)
		}
	}
}

func TestPortESearchModseqSummaryIsChecked(t *testing.T) {
	c := coreReplyClient(t, "* ESEARCH (TAG \"S000001\") MIN 2 MAX 3 MODSEQ 87\r\n")
	if err := portCheckESearch(c, "SEARCH RETURN (MIN MAX) 2:3 MODSEQ 1", false, map[string]uint64{"MIN": 2, "MAX": 3, "MODSEQ": 88}, nil); err == nil {
		t.Fatal("accepted wrong MODSEQ summary")
	}
}
