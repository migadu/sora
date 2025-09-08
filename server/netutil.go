package server

import (
	"net"
	"strconv"
)

// GetHostPortFromAddr extracts the host and port from a net.Addr.
// It returns the host string and port number.
// If parsing fails, it returns empty values or best-effort values.
func GetHostPortFromAddr(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		// This can happen for addresses without a port.
		return addr.String(), 0
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 0
	}
	return host, port
}
