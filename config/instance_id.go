package config

import (
	"os"
	"strings"
)

// FallbackInstanceID is the identity used when this node has no configured node_id and
// the operating system will not tell us our hostname. It is a fixed string on purpose:
// a random id would be unique but would change on every restart, and a restart under a
// new id abandons every pending upload the previous run queued (they are leased only by
// their creating instance). A stable wrong-ish name keeps a single node self-consistent
// across restarts; it only collides if several hostname-less nodes share a database,
// which is why resolving to it is logged as a warning at startup.
const FallbackInstanceID = "sora-unknown-host"

// FallbackMailHostname is the "by" host used when the operating system will not tell us
// our hostname. It is deliberately NOT FallbackInstanceID: the two names answer different
// questions, and a Received header is public. ".invalid" is reserved by RFC 2606 precisely
// so that a name which cannot resolve says so, rather than pretending to be a real host.
const FallbackMailHostname = "sora-unknown-host.invalid"

// NodeIdentity is the pair of names this node answers to. They are returned together
// because they are easy to confuse and expensive to confuse: one is an internal lease key,
// the other is published on every message the server delivers.
type NodeIdentity struct {
	// InstanceID keys the upload lease. Unique per node, stable across restarts.
	InstanceID string
	// MailHostname is the SMTP-visible name of this node.
	MailHostname string
}

// NodeIdentity resolves both of this node's names in one place, so a caller reaching for
// "the hostname" is forced to say which one it means.
func (c Config) NodeIdentity() NodeIdentity {
	return NodeIdentity{
		InstanceID:   c.InstanceID(),
		MailHostname: c.MailHostname(),
	}
}

// MailHostname returns the name this node publishes to other mail systems: the "by" host
// of the Received header LMTP and the delivery API stamp on every message, the domain of
// the Message-ID on vacation auto-replies, and the SMTP/IMAP/POP3 greeting.
//
// It is deliberately independent of cluster.node_id. node_id is a lease key whose only
// requirement is uniqueness within the cluster, so operators reasonably set it to an
// internal label ("node-1"); publishing that label as a mail host stamps a name that does
// not resolve into the trace headers of real mail, and mints vacation Message-IDs in a
// non-existent domain - a spam signal on a reply the user did not choose to send.
//
// The host's own name is the right source because it is the name the outside world already
// associates with this machine. It is not guaranteed to be fully qualified, which is why
// the server warns at startup when it is not (see logInstanceIdentity).
func (c Config) MailHostname() string {
	return ResolveMailHostname()
}

// ResolveMailHostname derives the SMTP-visible name from the host. It takes no config
// because nothing in the config may override it today; it exists as a named function so
// that every caller shares one derivation and a future explicit setting has one place to
// land.
func ResolveMailHostname() string {
	return mailHostnameFrom(os.Hostname)
}

// mailHostnameFrom is the pure form, with the hostname lookup injected for testing.
func mailHostnameFrom(hostnameFn func() (string, error)) string {
	if hostname, err := hostnameFn(); err == nil {
		if hostname = strings.TrimSpace(hostname); hostname != "" {
			return hostname
		}
	}
	return FallbackMailHostname
}

// InstanceID returns the identity this node writes into pending_uploads.instance_id and
// instance_heartbeats.instance_id.
//
// This is NOT the name the node announces to other mail systems - see MailHostname. And
// it is NOT cluster.node_id: that names this node on the gossip bus, and coupling the two
// would mean renaming the gossip node silently strands every queued upload. The three
// identities answer different questions and each resolves from its own source.
//
// pending_uploads.instance_id is a lease key, not a label: the message body of a pending
// upload is a file on the creating node's local disk, so db.AcquireAndLeasePendingUploads
// hands a row only to the instance named on it, and db.CleanupFailedUploads deletes the
// message once that instance stops writing heartbeats. Every writer of instance identity
// must therefore resolve it through this one function.
//
// The source is uploader.instance_id, defaulting to the hostname — the exact value
// pre-split binaries stamped, so an upgrade is lease-continuous with no re-stamping.
// Set it explicitly to run multiple instances on one host, or to pin the lease identity
// across a planned hostname change.
//
// WARNING - changing the resolved value strands queued uploads. Rows already in
// pending_uploads keep the old instance_id; no running instance will claim them, the old
// id stops heartbeating, and once the messages pass uploader.cleanup_grace_period the
// cleaner treats the owner as gone and deletes them. Before changing
// uploader.instance_id (or a node's hostname while it is unset), drain the queue: stop
// accepting mail, wait for pending_uploads to empty for the old id, and only then
// restart under the new one. The cleanup worker warns about any leftover owner by name
// (see cleaner.reportStrandedInstances).
func (c Config) InstanceID() string {
	return ResolveInstanceID(c.Uploader.InstanceID)
}

// ResolveInstanceID derives the instance identity from a configured uploader.instance_id.
// It exists separately from Config.InstanceID because sora-admin decodes the same
// config.toml into its own struct: both binaries write pending_uploads rows on the same
// host, so both must resolve the identity through this one derivation or the cleaner
// sees an owner that never heartbeats.
func ResolveInstanceID(configured string) string {
	return instanceIDFrom(configured, os.Hostname)
}

// instanceIDFrom is the pure form, with the hostname lookup injected so the derivation
// can be tested without a host.
func instanceIDFrom(configured string, hostnameFn func() (string, error)) string {
	// An explicit uploader.instance_id is the operator naming this node's upload spool,
	// so it wins over the ambient hostname.
	if configured := strings.TrimSpace(configured); configured != "" {
		return configured
	}
	if hostname, err := hostnameFn(); err == nil {
		if hostname = strings.TrimSpace(hostname); hostname != "" {
			return hostname
		}
	}
	return FallbackInstanceID
}
