package imap

import (
	"context"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

func newDisabledCapsTestServer(t *testing.T, opts IMAPServerOptions) *IMAPServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	opts.AppendLimit = DefaultAppendLimit
	opts.MaxConnections = 10
	opts.Config = &config.Config{}
	srv, err := New(ctx, "disabled-caps", "localhost", "127.0.0.1:0", &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// go-imap's CapSet.Has reports every extension IMAP4rev2 folds in (RFC 9051)
// as present while IMAP4rev2 is in the set, and both the CAPABILITY response
// and the command gates go through Has. disabled_caps deleted only the named
// key, so IDLE and ESEARCH stayed advertised and usable (#330).
func TestDisabledCaps_RemovesRev2ImpliedCapabilities(t *testing.T) {
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: []string{"IDLE", "ESEARCH"}})

	for _, c := range []imap.Cap{imap.CapIdle, imap.CapESearch, imap.CapIMAP4rev2} {
		if srv.caps.Has(c) {
			t.Errorf("disabled_caps = [IDLE ESEARCH]: server capabilities still have %s", c)
		}
	}
	// Dropping IMAP4rev2 must not take anything else away: the server keeps
	// speaking IMAP4rev1 with each remaining extension listed on its own.
	for _, c := range []imap.Cap{
		imap.CapIMAP4rev1, imap.CapMove, imap.CapNamespace, imap.CapUIDPlus,
		imap.CapSearchRes, imap.CapListStatus, imap.CapStatusSize, imap.CapChildren,
		imap.CapListExtended, imap.CapCondStore, imap.CapQResync,
	} {
		if !srv.caps.Has(c) {
			t.Errorf("disabled_caps = [IDLE ESEARCH] also removed %s", c)
		}
	}
}

// QRESYNC implies CONDSTORE in CapSet.Has (RFC 7162 §3.2), so disabling
// CONDSTORE alone left it advertised and enabled through QRESYNC.
func TestDisabledCaps_RemovesCapabilityImpliedByQResync(t *testing.T) {
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: []string{"CONDSTORE"}})

	for _, c := range []imap.Cap{imap.CapCondStore, imap.CapQResync} {
		if srv.caps.Has(c) {
			t.Errorf("disabled_caps = [CONDSTORE]: server capabilities still have %s", c)
		}
	}
	if !srv.caps.Has(imap.CapIMAP4rev2) {
		t.Error("disabled_caps = [CONDSTORE] removed IMAP4rev2, which does not imply CONDSTORE")
	}
}

// A capability IMAP4rev2 does not imply leaves IMAP4rev2 alone.
func TestDisabledCaps_KeepsRev2ForUnrelatedCapability(t *testing.T) {
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: []string{"THREAD=REFS"}})

	if srv.caps.Has("THREAD=REFS") {
		t.Error("disabled_caps = [THREAD=REFS]: still present")
	}
	if !srv.caps.Has(imap.CapIMAP4rev2) {
		t.Error("disabled_caps = [THREAD=REFS] removed IMAP4rev2")
	}
}

// client_filters follow the same rule as disabled_caps.
func TestClientFilter_RemovesCapabilityImpliedByQResync(t *testing.T) {
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{CapabilityFilters: []config.ClientCapabilityFilter{{
		ClientName:  "^buggy$",
		DisableCaps: []string{"CONDSTORE"},
	}}})

	caps := srv.caps.Copy()
	srv.filterCapabilitiesForClient(caps, &imap.IDData{Name: "buggy"}, "")
	for _, c := range []imap.Cap{imap.CapCondStore, imap.CapQResync} {
		if caps.Has(c) {
			t.Errorf("client filter disable_caps = [CONDSTORE]: session capabilities still have %s", c)
		}
	}
}
