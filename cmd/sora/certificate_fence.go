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

// TryHoldIssuance claims the right to order a certificate for domain, returning a release
// for a granted claim and a nil release when another node holds it.
func (f certificateIssuanceFence) TryHoldIssuance(ctx context.Context, domain string, ttl time.Duration) (func(context.Context), error) {
	name := db.CertificateIssuanceLock(domain)

	lock, err := f.rdb.TryAcquireNamedLockWithRetry(ctx, name, ttl)
	if err != nil {
		return nil, err
	}
	if lock == nil {
		return nil, nil
	}

	return func(releaseCtx context.Context) {
		// A failed release is not fatal: the claim expires on its own, so the only cost
		// is that the next order for this domain waits out the remaining ttl.
		if err := f.rdb.ReleaseNamedLockWithRetry(releaseCtx, lock); err != nil {
			logger.Warn("TLS: Failed to release certificate issuance claim - it will expire",
				"domain", domain, "error", err)
		}
	}, nil
}
