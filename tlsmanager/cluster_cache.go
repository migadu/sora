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
	logger.Debugf("[ClusterCache] Get certificate: %s (node: %s, leader: %s)",
		name, c.clusterManager.GetNodeID(), c.clusterManager.GetLeaderID())

	data, err := c.underlying.Get(ctx, name)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			logger.Debugf("[ClusterCache] Certificate not found: %s", name)
		} else {
			logger.Debugf("[ClusterCache] Error getting certificate %s: %v", name, err)
		}
		return nil, err
	}

	logger.Debugf("[ClusterCache] Certificate retrieved: %s", name)
	return data, nil
}

// Put stores a certificate in the cache (only leader can write)
func (c *ClusterAwareCache) Put(ctx context.Context, name string, data []byte) error {
	nodeID := c.clusterManager.GetNodeID()
	leaderID := c.clusterManager.GetLeaderID()

	logger.Infof("[ClusterCache] Put certificate request: %s (node: %s, leader: %s)",
		name, nodeID, leaderID)

	// Check if this node is the cluster leader
	if !c.clusterManager.IsLeader() {
		// Non-leader nodes should not write certificates
		// This prevents race conditions with Let's Encrypt
		logger.Warnf("[ClusterCache] Certificate request BLOCKED - not cluster leader: %s (leader %s will handle it)",
			name, leaderID)
		return fmt.Errorf("only cluster leader can request new certificates (current leader: %s, this node: %s)",
			leaderID, nodeID)
	}

	logger.Infof("[ClusterCache] Cluster leader storing certificate: %s", name)
	err := c.underlying.Put(ctx, name, data)
	if err != nil {
		logger.Errorf("[ClusterCache] Failed to store certificate %s: %v", name, err)
		return err
	}

	logger.Infof("[ClusterCache] Certificate stored by leader: %s", name)
	return nil
}

// Delete removes a certificate from the cache (only leader can delete)
func (c *ClusterAwareCache) Delete(ctx context.Context, name string) error {
	nodeID := c.clusterManager.GetNodeID()
	leaderID := c.clusterManager.GetLeaderID()

	logger.Debugf("[ClusterCache] Delete certificate request: %s (node: %s, leader: %s)",
		name, nodeID, leaderID)

	// Check if this node is the cluster leader
	if !c.clusterManager.IsLeader() {
		logger.Debugf("[ClusterCache] Skipping certificate Delete (not cluster leader): %s (leader: %s)",
			name, leaderID)
		return fmt.Errorf("only cluster leader can delete certificates (current leader: %s)", leaderID)
	}

	logger.Infof("[ClusterCache] Cluster leader deleting certificate: %s", name)
	err := c.underlying.Delete(ctx, name)
	if err != nil {
		logger.Errorf("[ClusterCache] Failed to delete certificate %s: %v", name, err)
		return err
	}

	logger.Infof("[ClusterCache] Certificate deleted by leader: %s", name)
	return nil
}
