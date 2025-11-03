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
	logger.Debug("ClusterCache: Get certificate", "name", name, "node", c.clusterManager.GetNodeID(), "leader", c.clusterManager.GetLeaderID())

	data, err := c.underlying.Get(ctx, name)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			logger.Debug("ClusterCache: Certificate not found", "name", name)
		} else {
			logger.Debug("ClusterCache: Error getting certificate", "name", name, "error", err)
		}
		return nil, err
	}

	logger.Debug("ClusterCache: Certificate retrieved", "name", name)
	return data, nil
}

// Put stores a certificate in the cache (only leader can write)
func (c *ClusterAwareCache) Put(ctx context.Context, name string, data []byte) error {
	nodeID := c.clusterManager.GetNodeID()
	leaderID := c.clusterManager.GetLeaderID()

	logger.Info("ClusterCache: Put certificate request", "name", name,
		"node", nodeID, "leader", leaderID)

	// Check if this node is the cluster leader
	if !c.clusterManager.IsLeader() {
		// Non-leader nodes should not write certificates
		// This prevents race conditions with Let's Encrypt
		logger.Warn("ClusterCache: Certificate request BLOCKED - not cluster leader (leader will handle it)", "name", name, "leader", leaderID)
		return fmt.Errorf("only cluster leader can request new certificates (current leader: %s, this node: %s)",
			leaderID, nodeID)
	}

	logger.Info("ClusterCache: Cluster leader storing certificate", "name", name)
	err := c.underlying.Put(ctx, name, data)
	if err != nil {
		logger.Error("ClusterCache: Failed to store certificate", "name", name, "error", err)
		return err
	}

	logger.Info("ClusterCache: Certificate stored by leader", "name", name)
	return nil
}

// Delete removes a certificate from the cache (only leader can delete)
func (c *ClusterAwareCache) Delete(ctx context.Context, name string) error {
	nodeID := c.clusterManager.GetNodeID()
	leaderID := c.clusterManager.GetLeaderID()

	logger.Debug("ClusterCache: Delete certificate request", "name", name, "node", nodeID, "leader", leaderID)

	// Check if this node is the cluster leader
	if !c.clusterManager.IsLeader() {
		logger.Debug("ClusterCache: Skipping certificate delete (not cluster leader)", "name", name, "leader", leaderID)
		return fmt.Errorf("only cluster leader can delete certificates (current leader: %s)", leaderID)
	}

	logger.Info("ClusterCache: Cluster leader deleting certificate", "name", name)
	err := c.underlying.Delete(ctx, name)
	if err != nil {
		logger.Error("ClusterCache: Failed to delete certificate", "name", name, "error", err)
		return err
	}

	logger.Info("ClusterCache: Certificate deleted by leader", "name", name)
	return nil
}
