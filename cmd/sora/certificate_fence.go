package main

import (
	"context"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/tlsmanager"
)

// certificateIssuanceFence backs the TLS manager's issuance fence with a named database
// lock, so exactly one node in the cluster runs an ACME order for a given domain.
//
// It exists because gossip leadership is not an authority on "only me": cluster
// electLeader picks the smallest node id among the members the node can currently see,
// with no quorum, so a network partition elects a leader on both sides and each believes
// it is alone. Postgres cannot be partitioned into two writable copies, so a claim taken
// here settles it.
type certificateIssuanceFence struct {
	rdb *resilient.ResilientDatabase
}

// The fence is installed through an interface, so a signature drift would otherwise only
// surface at the call site as a confusing conversion error.
var _ tlsmanager.CertificateFence = certificateIssuanceFence{}

// TryHoldIssuance claims the right to order a certificate for domain, returning the
// granted claim and nil when another node holds it.
func (f certificateIssuanceFence) TryHoldIssuance(ctx context.Context, domain string, ttl time.Duration) (tlsmanager.IssuanceHold, error) {
	name := db.CertificateIssuanceLock(domain)

	lock, err := f.rdb.TryAcquireNamedLockWithRetry(ctx, name, ttl)
	if err != nil {
		return nil, err
	}
	if lock == nil {
		return nil, nil
	}
	return certificateIssuanceHold{rdb: f.rdb, domain: domain, lock: lock}, nil
}

// certificateIssuanceHold is a granted issuance claim: the lock row, named by its
// fencing token.
type certificateIssuanceHold struct {
	rdb    *resilient.ResilientDatabase
	domain string
	lock   *db.NamedLock
}

// Extend moves the claim's expiry to no earlier than ttl from now, reporting false once
// the claim is no longer this node's.
func (h certificateIssuanceHold) Extend(ctx context.Context, ttl time.Duration) (bool, error) {
	return h.rdb.ExtendNamedLockWithRetry(ctx, h.lock, ttl)
}

// Release gives the claim back before its expiry.
func (h certificateIssuanceHold) Release(ctx context.Context) {
	// A failed release is not fatal: the claim expires on its own, so the only cost is
	// that the next order for this domain waits out the remaining ttl.
	if err := h.rdb.ReleaseNamedLockWithRetry(ctx, h.lock); err != nil {
		logger.Warn("TLS: Failed to release certificate issuance claim - it will expire",
			"domain", h.domain, "error", err)
	}
}
