package imap

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
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

// go-imap lists SASL-IR, LITERAL-, UNSELECT and ENABLE with IMAP4rev1 whatever
// the configured set holds, so naming one in disabled_caps or client_filters
// cannot withdraw it. Removing what implies it (IMAP4rev2, and LITERAL+ for
// LITERAL-) would only downgrade the server while it stays advertised.
func TestDisabledCaps_KeepsImpliersOfAlwaysAdvertisedCapability(t *testing.T) {
	for _, c := range []imap.Cap{imap.CapSASLIR, imap.CapLiteralMinus, imap.CapUnselect, imap.CapEnable} {
		srv := newDisabledCapsTestServer(t, IMAPServerOptions{
			DisabledCaps: []string{string(c)},
			CapabilityFilters: []config.ClientCapabilityFilter{{
				ClientName:  "^buggy$",
				DisableCaps: []string{string(c)},
			}},
		})
		for _, keep := range []imap.Cap{imap.CapIMAP4rev2, imap.CapLiteralPlus} {
			if !srv.caps.Has(keep) {
				t.Errorf("disabled_caps = [%s] removed %s", c, keep)
			}
		}

		caps := srv.caps.Copy()
		srv.filterCapabilitiesForClient(caps, &imap.IDData{Name: "buggy"}, "")
		for _, keep := range []imap.Cap{imap.CapIMAP4rev2, imap.CapLiteralPlus} {
			if !caps.Has(keep) {
				t.Errorf("client filter disable_caps = [%s] removed %s", c, keep)
			}
		}
	}
}

// SORT=DISPLAY and ESORT extend the SORT command (RFC 5957 §1, RFC 5267 §3),
// but go-imap's Has does not count them as implying SORT, so disabling SORT
// left both advertised (#508). Disabling one of them alone keeps SORT.
func TestDisabledCaps_RemovesSortExtensions(t *testing.T) {
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: []string{"SORT"}})
	for _, c := range []imap.Cap{imap.CapSort, imap.CapSortDisplay, imap.CapESort} {
		if srv.caps.Has(c) {
			t.Errorf("disabled_caps = [SORT]: server capabilities still have %s", c)
		}
	}
	if !srv.caps.Has(imap.CapIMAP4rev2) {
		t.Error("disabled_caps = [SORT] removed IMAP4rev2, which does not imply SORT")
	}

	for _, name := range []string{"SORT=DISPLAY", "ESORT"} {
		srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: []string{name}})
		if !srv.caps.Has(imap.CapSort) {
			t.Errorf("disabled_caps = [%s] removed SORT", name)
		}
	}
}

// newDisabledCapsTestSession returns a session of srv with no user, mailbox or
// database behind it.
func newDisabledCapsTestSession(srv *IMAPServer) *IMAPSession {
	s := &IMAPSession{server: srv}
	s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, context.Background(), "IMAP", func(string, ...any) {})
	return s
}

// callHandler runs a session command handler and reports a panic as an error:
// the test session has no user or database, so a handler that does not refuse
// the command up front runs into them.
func callHandler(call func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("handler ran past the capability check (panic: %v)", r)
		}
	}()
	return call()
}

// disabledCapCommands are the commands, or command arguments, of capabilities
// that disabled_caps and client_filters can withdraw. go-imap dispatches them to
// the session whenever it implements them, whatever CAPABILITY said.
var disabledCapCommands = []struct {
	cap  string
	name string
	call func(s *IMAPSession) error
}{
	{"MOVE", "MOVE", func(s *IMAPSession) error {
		return s.Move(context.Background(), nil, imap.SeqSetNum(1), "Trash")
	}},
	{"NAMESPACE", "NAMESPACE", func(s *IMAPSession) error {
		_, err := s.Namespace(context.Background())
		return err
	}},
	{"STATUS=SIZE", "STATUS (SIZE)", func(s *IMAPSession) error {
		_, err := s.Status(context.Background(), "INBOX", &imap.StatusOptions{Size: true})
		return err
	}},
	{"STATUS=SIZE", "LIST RETURN (STATUS (SIZE))", func(s *IMAPSession) error {
		return s.List(context.Background(), nil, "", []string{"*"}, &imap.ListOptions{ReturnStatus: &imap.StatusOptions{Size: true}})
	}},
	{"METADATA", "GETMETADATA", func(s *IMAPSession) error {
		_, err := s.GetMetadata(context.Background(), "", []string{"/shared/comment"}, &imap.GetMetadataOptions{})
		return err
	}},
	{"METADATA", "SETMETADATA", func(s *IMAPSession) error {
		v := []byte("x")
		return s.SetMetadata(context.Background(), "", map[string]*[]byte{"/private/comment": &v})
	}},
	{"SORT", "SORT", func(s *IMAPSession) error {
		_, err := s.Sort(context.Background(), imapserver.NumKindSeq, []imap.SortCriterion{{Key: imap.SortKeyDate}}, "UTF-8", &imap.SearchCriteria{}, &imap.SortOptions{ReturnAll: true})
		return err
	}},
	{"SORT=DISPLAY", "SORT (DISPLAYFROM)", func(s *IMAPSession) error {
		_, err := s.Sort(context.Background(), imapserver.NumKindSeq, []imap.SortCriterion{{Key: imap.SortKeyDisplayFrom}}, "UTF-8", &imap.SearchCriteria{}, &imap.SortOptions{ReturnAll: true})
		return err
	}},
}

func assertRefusedAsBad(t *testing.T, how, name string, err error) {
	t.Helper()
	var imapErr *imap.Error
	if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeBad {
		t.Errorf("%s: %s was not refused with BAD: %v", how, name, err)
	}
}

// disabled_caps stopped only the advertising of MOVE, NAMESPACE, STATUS=SIZE,
// METADATA and SORT: their commands kept working (#508). RFC 9051 §6 gives
// "BAD - command unknown or arguments invalid" as the result of each command.
func TestDisabledCaps_RefusesCommandsOfDisabledCapability(t *testing.T) {
	for _, tc := range disabledCapCommands {
		srv := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: []string{tc.cap}})
		s := newDisabledCapsTestSession(srv)
		err := callHandler(func() error { return tc.call(s) })
		assertRefusedAsBad(t, "disabled_caps = ["+tc.cap+"]", tc.name, err)
	}
}

// client_filters withdraw a capability from one session; its commands must be
// refused in that session as with disabled_caps.
func TestClientFilter_RefusesCommandsOfDisabledCapability(t *testing.T) {
	for _, tc := range disabledCapCommands {
		srv := newDisabledCapsTestServer(t, IMAPServerOptions{CapabilityFilters: []config.ClientCapabilityFilter{{
			ClientName:  "^buggy$",
			DisableCaps: []string{tc.cap},
		}}})
		s := newDisabledCapsTestSession(srv)
		caps := srv.caps.Copy()
		srv.filterCapabilitiesForClient(caps, &imap.IDData{Name: "buggy"}, "")
		s.sessionCaps.Store(caps)
		err := callHandler(func() error { return tc.call(s) })
		assertRefusedAsBad(t, "client filter disable_caps = ["+tc.cap+"]", tc.name, err)
	}
}
