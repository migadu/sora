// +build linux freebsd darwin openbsd netbsd

package server

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// MakeListenControl creates a Control function for net.ListenConfig that sets the listen backlog.
// The backlog parameter specifies the maximum length of the queue of pending connections.
//
// Why this matters:
// - Small backlog (default SOMAXCONN = 128-512) causes SYN packets to be dropped when under load
// - Dropped SYN packets trigger TCP retransmissions with exponential backoff (1s, 3s, 6s, 12s, 24s...)
// - This leads to connection delays of ~60 seconds before clients can connect
// - Larger backlog (4096-8192) allows the kernel to queue more connections during bursts
//
// Platform notes:
// - FreeBSD: Must call listen() with custom backlog BEFORE net.Listen() wraps the socket
// - Linux/Darwin/Others: Call listen() in Control function; net package's listen() call will be a no-op
//
// How it works:
// 1. net.ListenConfig creates a socket and calls this Control function
// 2. We call listen() with the custom backlog on the raw file descriptor
// 3. net.ListenConfig tries to call listen() again, which is a no-op (already listening)
// 4. The socket is now listening with our custom backlog
func MakeListenControl(backlog int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var controlErr error
		err := c.Control(func(fd uintptr) {
			// Call listen() directly with our custom backlog
			// This must be done before net.ListenConfig wraps the socket
			if err := unix.Listen(int(fd), backlog); err != nil {
				controlErr = err
				return
			}
		})
		if err != nil {
			return err
		}
		return controlErr
	}
}
