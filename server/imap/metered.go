package imap

import (
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/pkg/metrics"
)

// meteredSession wraps an *IMAPSession to record per-command throughput and
// latency metrics (sora_commands_total / sora_command_duration_seconds) for
// every IMAP command, in one place, instead of hand-rolling a recordMetrics
// closure inside each handler.
//
// It embeds *IMAPSession, so all methods (including the optional extension
// interfaces the go-imap server probes via type assertion — SessionMove,
// SessionNamespace, SessionSASL, SessionAppendLimit, SessionCapabilities,
// SessionMetadata, SessionACL, SessionThread, SessionMultiSearch, SessionID,
// etc.) are promoted automatically. We override only the command methods we
// want to time; every override delegates to the embedded session and keeps the
// exact same signature, so interface satisfaction is unchanged.
//
// Deliberately NOT overridden (left promoted, untimed here):
//   - Append, Fetch: already self-instrument with bespoke timing semantics
//     (APPEND resets its timer to exclude slow-client upload from latency;
//     FETCH emits finer-grained statuses). Timing them here would double-count.
//   - Idle: long-lived (blocks until client DONE); tracked via the
//     sora_imap_idle_connections_current gauge, not command latency.
//   - Poll: server-driven mailbox sync between commands, not a client command.
//   - Login/Authenticate: covered by authentication metrics.
//   - Close/Unselect/Context/GetCapabilities/AppendLimit/ID: connection or
//     state plumbing, not user-visible command latency.
type meteredSession struct {
	*IMAPSession
}

// Compile-time guarantees that the wrapper still satisfies every optional
// session interface the go-imap server probes via type assertion. If an
// override here ever drifts from the real signature (which would silently make
// the server treat that command as unsupported), these break the build instead.
var (
	_ imapserver.Session             = (*meteredSession)(nil)
	_ imapserver.SessionNamespace    = (*meteredSession)(nil)
	_ imapserver.SessionMove         = (*meteredSession)(nil)
	_ imapserver.SessionSASL         = (*meteredSession)(nil)
	_ imapserver.SessionAppendLimit  = (*meteredSession)(nil)
	_ imapserver.SessionCapabilities = (*meteredSession)(nil)
	_ imapserver.SessionMetadata     = (*meteredSession)(nil)
	_ imapserver.SessionACL          = (*meteredSession)(nil)
	_ imapserver.SessionThread       = (*meteredSession)(nil)
	_ imapserver.SessionMultiSearch  = (*meteredSession)(nil)
	_ imapserver.SessionID           = (*meteredSession)(nil)
)

// newMeteredSession wraps an IMAP session for command metric collection.
func newMeteredSession(s *IMAPSession) imapserver.Session {
	return &meteredSession{IMAPSession: s}
}

// recordCommand emits the throughput counter and latency histogram for a single
// command invocation. status is derived from whether the handler returned an error.
func recordCommand(command string, start time.Time, err error) {
	status := "success"
	if err != nil {
		status = "failure"
	}
	metrics.CommandsTotal.WithLabelValues("imap", command, status).Inc()
	metrics.CommandDuration.WithLabelValues("imap", command).Observe(time.Since(start).Seconds())
}

// --- Authenticated state ---

func (m *meteredSession) Select(mboxName string, options *imap.SelectOptions) (*imap.SelectData, error) {
	start := time.Now()
	data, err := m.IMAPSession.Select(mboxName, options)
	recordCommand("SELECT", start, err)
	return data, err
}

func (m *meteredSession) Create(name string, options *imap.CreateOptions) error {
	start := time.Now()
	err := m.IMAPSession.Create(name, options)
	recordCommand("CREATE", start, err)
	return err
}

func (m *meteredSession) Delete(mboxName string) error {
	start := time.Now()
	err := m.IMAPSession.Delete(mboxName)
	recordCommand("DELETE", start, err)
	return err
}

func (m *meteredSession) Rename(existingName, newName string, options *imap.RenameOptions) error {
	start := time.Now()
	err := m.IMAPSession.Rename(existingName, newName, options)
	recordCommand("RENAME", start, err)
	return err
}

func (m *meteredSession) Subscribe(mailboxName string) error {
	start := time.Now()
	err := m.IMAPSession.Subscribe(mailboxName)
	recordCommand("SUBSCRIBE", start, err)
	return err
}

func (m *meteredSession) Unsubscribe(mailboxName string) error {
	start := time.Now()
	err := m.IMAPSession.Unsubscribe(mailboxName)
	recordCommand("UNSUBSCRIBE", start, err)
	return err
}

func (m *meteredSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	start := time.Now()
	err := m.IMAPSession.List(w, ref, patterns, options)
	recordCommand("LIST", start, err)
	return err
}

func (m *meteredSession) Status(mboxName string, options *imap.StatusOptions) (*imap.StatusData, error) {
	start := time.Now()
	data, err := m.IMAPSession.Status(mboxName, options)
	recordCommand("STATUS", start, err)
	return data, err
}

func (m *meteredSession) Namespace() (*imap.NamespaceData, error) {
	start := time.Now()
	data, err := m.IMAPSession.Namespace()
	recordCommand("NAMESPACE", start, err)
	return data, err
}

// --- Selected state ---

func (m *meteredSession) Expunge(w *imapserver.ExpungeWriter, uidSet *imap.UIDSet) error {
	start := time.Now()
	err := m.IMAPSession.Expunge(w, uidSet)
	recordCommand("EXPUNGE", start, err)
	return err
}

func (m *meteredSession) Search(numKind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	start := time.Now()
	data, err := m.IMAPSession.Search(numKind, criteria, options)
	recordCommand("SEARCH", start, err)
	return data, err
}

func (m *meteredSession) Sort(numKind imapserver.NumKind, sortCriteria []imap.SortCriterion, charset string, searchCriteria *imap.SearchCriteria, options *imap.SortOptions) (*imap.SortData, error) {
	start := time.Now()
	data, err := m.IMAPSession.Sort(numKind, sortCriteria, charset, searchCriteria, options)
	recordCommand("SORT", start, err)
	return data, err
}

func (m *meteredSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	start := time.Now()
	err := m.IMAPSession.Store(w, numSet, flags, options)
	recordCommand("STORE", start, err)
	return err
}

func (m *meteredSession) Copy(numSet imap.NumSet, mboxName string) (*imap.CopyData, error) {
	start := time.Now()
	data, err := m.IMAPSession.Copy(numSet, mboxName)
	recordCommand("COPY", start, err)
	return data, err
}

func (m *meteredSession) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	start := time.Now()
	err := m.IMAPSession.Move(w, numSet, dest)
	recordCommand("MOVE", start, err)
	return err
}

func (m *meteredSession) Thread(numKind imapserver.NumKind, algorithm imap.ThreadAlgorithm, charset string, criteria *imap.SearchCriteria) ([]imap.ThreadData, error) {
	start := time.Now()
	data, err := m.IMAPSession.Thread(numKind, algorithm, charset, criteria)
	recordCommand("THREAD", start, err)
	return data, err
}

func (m *meteredSession) MultiSearch(numKind imapserver.NumKind, mailboxes []string, criteria *imap.SearchCriteria, options *imap.SearchOptions) ([]*imap.SearchData, error) {
	start := time.Now()
	data, err := m.IMAPSession.MultiSearch(numKind, mailboxes, criteria, options)
	recordCommand("MULTISEARCH", start, err)
	return data, err
}

// --- METADATA (RFC 5464) ---

func (m *meteredSession) GetMetadata(mailbox string, entries []string, options *imap.GetMetadataOptions) (*imap.GetMetadataData, error) {
	start := time.Now()
	data, err := m.IMAPSession.GetMetadata(mailbox, entries, options)
	recordCommand("GETMETADATA", start, err)
	return data, err
}

func (m *meteredSession) SetMetadata(mailbox string, entries map[string]*[]byte) error {
	start := time.Now()
	err := m.IMAPSession.SetMetadata(mailbox, entries)
	recordCommand("SETMETADATA", start, err)
	return err
}

// --- ACL (RFC 4314) ---

func (m *meteredSession) GetACL(mailbox string) (*imap.GetACLData, error) {
	start := time.Now()
	data, err := m.IMAPSession.GetACL(mailbox)
	recordCommand("GETACL", start, err)
	return data, err
}

func (m *meteredSession) SetACL(mailbox string, identifier imap.RightsIdentifier, modification imap.RightModification, rights imap.RightSet) error {
	start := time.Now()
	err := m.IMAPSession.SetACL(mailbox, identifier, modification, rights)
	recordCommand("SETACL", start, err)
	return err
}

func (m *meteredSession) DeleteACL(mailbox string, identifier imap.RightsIdentifier) error {
	start := time.Now()
	err := m.IMAPSession.DeleteACL(mailbox, identifier)
	recordCommand("DELETEACL", start, err)
	return err
}

func (m *meteredSession) ListRights(mailbox string, identifier imap.RightsIdentifier) (*imap.ListRightsData, error) {
	start := time.Now()
	data, err := m.IMAPSession.ListRights(mailbox, identifier)
	recordCommand("LISTRIGHTS", start, err)
	return data, err
}

func (m *meteredSession) MyRights(mailbox string) (*imap.MyRightsData, error) {
	start := time.Now()
	data, err := m.IMAPSession.MyRights(mailbox)
	recordCommand("MYRIGHTS", start, err)
	return data, err
}
