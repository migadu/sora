package health

import (
	"context"
	"sort"
	"testing"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

type fakeLookupWithBreaker struct {
	breaker *circuitbreaker.CircuitBreaker
}

func (f fakeLookupWithBreaker) HealthCheck(context.Context) error { return nil }
func (f fakeLookupWithBreaker) GetCircuitBreaker() *circuitbreaker.CircuitBreaker {
	return f.breaker
}

// TestRemoteLookupCheckNames: the lookup client's breaker check follows the
// circuit_breaker_<x> naming of the relay breakers. It used to be registered as
// circuit_breaker_remotelookup_http_circuit_breaker_<name>, since
// RegisterCircuitBreakerCheck adds the prefix itself.
func TestRemoteLookupCheckNames(t *testing.T) {
	hi := NewHealthIntegration(nil)
	breaker := circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{Name: "test"})

	hi.RegisterRemoteLookupCheck(fakeLookupWithBreaker{breaker}, "imap-proxy")

	var names []string
	for name := range hi.GetCurrentHealthStatus() {
		names = append(names, name)
	}
	sort.Strings(names)
	want := []string{"circuit_breaker_remotelookup_http_imap-proxy", "remotelookup_http_imap-proxy"}
	if len(names) != len(want) || names[0] != want[0] || names[1] != want[1] {
		t.Errorf("registered checks %q, want %q", names, want)
	}
}
