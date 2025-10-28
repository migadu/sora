package db

import (
	"time"
)

// ConnectionInfo represents an active connection
type ConnectionInfo struct {
	ID              int64
	AccountID       int64
	Protocol        string
	ClientAddr      string
	ServerAddr      string
	InstanceID      string
	ConnectedAt     time.Time
	LastActivity    time.Time
	ShouldTerminate bool
	Email           string // Primary email for display
	IsProxy         bool   // Whether this is a proxy connection
}

// ConnectionStats represents aggregated connection statistics
type ConnectionStats struct {
	TotalConnections      int64
	ConnectionsByProtocol map[string]int64
	ConnectionsByServer   map[string]int64
	Users                 []ConnectionInfo
}

// NOTE: All connection tracking functions have been removed.
// Connection tracking has migrated from database to in-memory gossip/local tracking.
//
// Previously removed write functions:
// - RegisterConnection, UpdateConnectionActivity, UnregisterConnection
// - BatchRegisterConnections, BatchUpdateConnections
// - CleanupConnectionsByInstanceID
//
// Recently removed read functions:
// - GetActiveConnections, GetConnectionStats, GetUserConnections
// - GetTerminatedConnectionsByInstance
//
// For connection tracking, use server/proxy/connection_tracker.go instead.
// For viewing connections via API, use the HTTP Admin API endpoints:
// - GET /admin/connections (list all connections)
// - GET /admin/connections/stats (connection statistics)
// - GET /admin/connections/user/{email} (user-specific connections)
// - POST /admin/connections/kick (kick user)
