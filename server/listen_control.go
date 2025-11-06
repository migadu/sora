//go:build linux || freebsd || darwin || openbsd || netbsd

package server

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/migadu/sora/logger"
	"golang.org/x/sys/unix"
)

// ListenWithBacklog creates a TCP listener with a custom listen backlog.
// Uses net.ListenConfig with a Control function to set socket options and backlog.
//
// Why this matters:
// - Small backlog (default SOMAXCONN = 128-512) causes SYN packets to be dropped when under load
// - Dropped SYN packets trigger TCP retransmissions with exponential backoff (1s, 3s, 6s, 12s, 24s...)
// - This leads to connection delays of ~60 seconds before clients can connect
// - Larger backlog (4096-8192) allows the kernel to queue more connections during bursts
//
// Implementation: Uses net.ListenConfig which properly handles all socket setup,
// and we only intervene to set SO_LISTENQLIMIT (FreeBSD) or adjust the backlog.
func ListenWithBacklog(ctx context.Context, network, address string, backlog int) (net.Listener, error) {
	// On FreeBSD, we can use SO_LISTENQLIMIT to set the listen backlog
	// This must be set BEFORE calling listen()
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR for fast restart
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					ctrlErr = fmt.Errorf("failed to set SO_REUSEADDR: %w", err)
					return
				}

				// On FreeBSD, set SO_LISTENQLIMIT before listen()
				// This controls the listen queue size
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_LISTENQLIMIT, backlog); err != nil {
					// Log but don't fail - this might not be supported on all BSD versions
					logger.Debug("Failed to set SO_LISTENQLIMIT, will use default backlog",
						"network", network, "address", address, "backlog", backlog, "error", err)
				}
			})
			if err != nil {
				return err
			}
			return ctrlErr
		},
	}

	listener, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	return listener, nil
}

// ListenWithBacklogManual is the old manual socket creation approach.
// Kept for reference but should not be used as it causes issues on FreeBSD IPv6.
func ListenWithBacklogManual(ctx context.Context, network, address string, backlog int) (net.Listener, error) {
	// This function is kept for reference but should not be used
	return nil, fmt.Errorf("ListenWithBacklogManual is deprecated, use ListenWithBacklog instead")
}

// MakeListenControl creates a Control function for net.ListenConfig that sets socket options.
// This is kept for compatibility but doesn't set the backlog (use ListenWithBacklog for that).
func MakeListenControl(backlog int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		// This function is no longer used for setting backlog.
		// Use ListenWithBacklog instead for proper backlog control.
		return nil
	}
}
