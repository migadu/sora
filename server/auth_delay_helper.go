package server

import (
	"context"
	"github.com/migadu/sora/logger"
	"net"
	"time"
)

// AuthDelayHelper provides delay functionality for authentication rate limiting
type AuthDelayHelper interface {
	GetAuthenticationDelay(remoteAddr net.Addr) time.Duration
}

// ApplyAuthenticationDelay applies progressive delays before authentication attempts
func ApplyAuthenticationDelay(ctx context.Context, limiter interface{}, remoteAddr net.Addr, protocol string) {
	delayHelper, ok := limiter.(AuthDelayHelper)
	if !ok || delayHelper == nil {
		return
	}

	delay := delayHelper.GetAuthenticationDelay(remoteAddr)
	if delay > 0 {
		ip, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			ip = remoteAddr.String()
		}

		logger.Debug("Auth delay: Applying delay", "protocol", protocol, "delay", delay, "ip", ip)

		// Use context-aware delay to allow cancellation
		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-timer.C:
			// Delay completed normally
			logger.Debug("Auth delay: Delay completed", "protocol", protocol, "ip", ip)
		case <-ctx.Done():
			// Context cancelled (connection closed, server shutdown, etc.)
			logger.Debug("Auth delay: Delay cancelled", "protocol", protocol, "ip", ip, "error", ctx.Err())
			return
		}
	}
}

// GetIPString safely extracts IP address from net.Addr
func GetIPString(addr net.Addr) string {
	if ip, _, err := net.SplitHostPort(addr.String()); err == nil {
		return ip
	}
	return addr.String()
}
