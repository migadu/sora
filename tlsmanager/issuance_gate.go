package tlsmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// defaultIssuanceWait bounds how long a handshake on a node that does not issue waits
	// for the leader's certificate to reach the shared cache before it gives up.
	defaultIssuanceWait = 5 * time.Second
	// defaultIssuancePoll is the interval between shared-cache reads during that wait.
	defaultIssuancePoll = 1 * time.Second
)

// errIssuanceDeferred is reported in place of a cache miss on a node that must not order
// certificates. autocert reads a cache miss as permission to start an ACME order, so a
// node whose order would be thrown away has to answer with anything but ErrCacheMiss.
var errIssuanceDeferred = errors.New("certificate issuance deferred to the cluster leader")

// issuanceGate is the last point in front of an ACME order at which issuance can still
// be declined: autocert reads the cache for a certificate it does not hold in memory,
// and orders one the moment that read reports the certificate absent.
type issuanceGate struct {
	underlying autocert.Cache
	manager    *Manager
}

func newIssuanceGate(cache autocert.Cache, m *Manager) *issuanceGate {
	return &issuanceGate{underlying: cache, manager: m}
}

func (g *issuanceGate) Get(ctx context.Context, name string) ([]byte, error) {
	data, err := g.underlying.Get(ctx, name)
	if !errors.Is(err, autocert.ErrCacheMiss) {
		return data, err
	}

	domain, isCertificate := certificateDomain(name)
	if !isCertificate {
		return nil, err
	}
	if refusal := g.manager.refuseIssuance(domain); refusal != nil {
		return nil, refusal
	}

	logger.Info("TLS: Certificate not in cache - issuance allowed", "domain", domain)
	return nil, err
}

func (g *issuanceGate) Put(ctx context.Context, name string, data []byte) error {
	err := g.underlying.Put(ctx, name, data)
	// The order is finished either way - a failed Put does not mean it is still running -
	// so the cluster-wide claim is given back regardless.
	if domain, isCertificate := certificateDomain(name); isCertificate {
		g.manager.releaseIssuance(domain)
	}
	return err
}

func (g *issuanceGate) Delete(ctx context.Context, name string) error {
	return g.underlying.Delete(ctx, name)
}

func (g *issuanceGate) unwrap() autocert.Cache {
	return g.underlying
}

// certificateDomain reports the domain whose certificate a cache entry holds. autocert
// keeps certificates under "<domain>" and "<domain>+rsa"; its other entries hold
// challenge material whose absence does not start an order.
func certificateDomain(name string) (string, bool) {
	switch {
	case name == "acme_account+key", name == "acme_account.key":
		return "", false
	// Both are suffixes: autocert builds them as httpTokenCacheKey = base(path)+"+http-01"
	// and certKey = domain+"+token" for the tls-alpn-01 challenge certificate.
	case strings.HasSuffix(name, "+http-01"), strings.HasSuffix(name, "+token"):
		return "", false
	}
	return strings.TrimSuffix(name, "+rsa"), true
}

// mayIssue reports whether this node is allowed to order certificates at all.
func (m *Manager) mayIssue() bool {
	return m.clusterManager == nil || m.clusterManager.IsLeader()
}

// refuseIssuance reports why this node must not order a certificate for domain now, or
// nil if it may.
func (m *Manager) refuseIssuance(domain string) error {
	if !m.mayIssue() {
		leader := m.clusterManager.GetLeaderID()
		// Debug because a waiting handshake arrives here on every poll; the wait itself
		// is reported once, at Info.
		logger.Debug("TLS: Not ordering certificate - this node is not the cluster leader", "domain", domain, "leader", leader)
		return fmt.Errorf("%w: %s (leader: %s, this node: %s)", errIssuanceDeferred, domain, leader, m.clusterManager.GetNodeID())
	}

	if limited, retryAfter := m.isRateLimited(domain); limited {
		logger.Warn("TLS: Not ordering certificate - domain is rate-limited", "domain", domain, "retry_after", retryAfter)
		return fmt.Errorf("%s is rate limited until %s", domain, retryAfter.Format(time.RFC3339))
	}

	// Last: leadership above says this node SHOULD issue, the fence says whether it MAY.
	// Under a partition the check above passes on both sides, because each side elected
	// its own leader; only one of them can hold the claim.
	return m.holdIssuance(domain)
}

// awaitIssuedCertificate waits, bounded, for a certificate ordered by the cluster leader
// to reach the shared cache. Nothing on this node will produce it, so the only options
// are the leader's certificate or a failed handshake.
func (m *Manager) awaitIssuedCertificate(hello *tls.ClientHelloInfo, get func(*tls.ClientHelloInfo) (*tls.Certificate, error), cause error) (*tls.Certificate, error) {
	if m.issuanceWait <= 0 || m.issuancePoll <= 0 {
		return nil, cause
	}

	parent := hello.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, m.issuanceWait)
	defer cancel()

	logger.Info("TLS: Waiting for the cluster leader to publish a certificate", "domain", hello.ServerName, "wait", m.issuanceWait)

	ticker := time.NewTicker(m.issuancePoll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, cause
		case <-ticker.C:
			cert, err := get(hello)
			if err == nil {
				logger.Info("TLS: Serving certificate published by the cluster leader", "domain", hello.ServerName)
				return cert, nil
			}
			if !errors.Is(err, errIssuanceDeferred) {
				return nil, err
			}
			cause = err
		}
	}
}

// issuanceFence refuses ACME requests made by a node that must not issue. autocert
// reaches Let's Encrypt from paths that never read the certificate cache - its
// background renewal goroutine among them - and every one of them passes through here.
type issuanceFence struct {
	manager *Manager
	base    http.RoundTripper
}

func (f *issuanceFence) RoundTrip(req *http.Request) (*http.Response, error) {
	if !f.manager.mayIssue() {
		return nil, fmt.Errorf("%w: request to %s (leader: %s, this node: %s)", errIssuanceDeferred,
			req.URL.Host, f.manager.clusterManager.GetLeaderID(), f.manager.clusterManager.GetNodeID())
	}
	return f.base.RoundTrip(req)
}
