package tlsmanager

import (
	"context"
	"fmt"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme/autocert"
)

// ClusterAwareCache wraps an autocert.Cache and only allows the cluster leader
// to write new certificates. All nodes can read certificates from the cache.
type ClusterAwareCache struct {
	underlying     autocert.Cache
	clusterManager *cluster.Manager
}

// NewClusterAwareCache creates a new cluster-aware certificate cache
func NewClusterAwareCache(cache autocert.Cache, clusterMgr *cluster.Manager) *ClusterAwareCache {
	return &ClusterAwareCache{
		underlying:     cache,
		clusterManager: clusterMgr,
	}
}

// Get retrieves a certificate from the cache (all nodes can read)
func (c *ClusterAwareCache) Get(ctx context.Context, name string) ([]byte, error) {
	return c.underlying.Get(ctx, name)
}

// Put stores a certificate in the cache (only leader can write)
func (c *ClusterAwareCache) Put(ctx context.Context, name string, data []byte) error {
	// Check if this node is the cluster leader
	if !c.clusterManager.IsLeader() {
		// Non-leader nodes should not write certificates
		// This prevents race conditions with Let's Encrypt
		leaderID := c.clusterManager.GetLeaderID()
		logger.Infof("Certificate request blocked - not cluster leader: %s (current leader: %s will handle it)",
			name, leaderID)
		return fmt.Errorf("only cluster leader can request new certificates (current leader: %s, this node: %s)",
			leaderID, c.clusterManager.GetNodeID())
	}

	logger.Infof("Cluster leader storing certificate: %s", name)
	return c.underlying.Put(ctx, name, data)
}

// Delete removes a certificate from the cache (only leader can delete)
func (c *ClusterAwareCache) Delete(ctx context.Context, name string) error {
	// Check if this node is the cluster leader
	if !c.clusterManager.IsLeader() {
		logger.Debugf("Skipping certificate Delete (not cluster leader): %s (leader: %s)",
			name, c.clusterManager.GetLeaderID())
		return fmt.Errorf("only cluster leader can delete certificates (current leader: %s)",
			c.clusterManager.GetLeaderID())
	}

	logger.Infof("Cluster leader deleting certificate: %s", name)
	return c.underlying.Delete(ctx, name)
}
