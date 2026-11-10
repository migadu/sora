package userapiproxy

import (
	"fmt"
	"net/http"

	"github.com/migadu/sora/server/proxy"
)

// HTTP keep-alive reuse skips DialTLSContext, so transport identity must include
// the pool and the DNS snapshot that selected its trust policy, not just verify.
type backendTransportKey struct {
	pool                  string
	snapshot              uint64
	verify, proxyProtocol bool
}

type boundBackendTransport struct {
	transport http.RoundTripper
	bound     *proxy.BackendRoute
}

func (t boundBackendTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.bound.Validate(); err != nil {
		return nil, err
	}
	return t.transport.RoundTrip(r)
}

func (s *Server) transportFor(route backendRoute, bound *proxy.BackendRoute) (http.RoundTripper, error) {
	if err := bound.Validate(); err != nil {
		return nil, err
	}
	// Literal server fixtures can supply a transport without a constructor.
	if s.newTransport == nil {
		return boundBackendTransport{s.legacyTransportFor(route), bound}, nil
	}
	// The transport already separates origins by scheme/host/port. TLS names
	// come from each request's binding, so arbitrary lookup pins need no extra
	// per-address transport map.
	key := backendTransportKey{pool: bound.PoolName(), snapshot: bound.SnapshotID(), verify: route.tlsVerify, proxyProtocol: route.proxyProtocol}
	s.transportMu.Lock()
	if key.snapshot < s.transportSnapshot {
		s.transportMu.Unlock()
		return nil, fmt.Errorf("%w: transport DNS snapshot retired", proxy.ErrBackendOutsidePool)
	}
	var retired []*http.Transport
	if key.snapshot > s.transportSnapshot {
		for _, tr := range s.poolTransports {
			retired = append(retired, tr)
		}
		s.poolTransports = make(map[backendTransportKey]*http.Transport)
		s.transportSnapshot = key.snapshot
	}
	tr := s.poolTransports[key]
	if tr == nil {
		tr = s.newTransport(route.tlsVerify)
		s.poolTransports[key] = tr
	}
	s.transportMu.Unlock()
	// In-flight requests retain their old transport until completion, but no
	// later request can select it, even when an old socket returns to idle.
	for _, old := range retired {
		old.CloseIdleConnections()
	}
	return boundBackendTransport{tr, bound}, nil
}

func (s *Server) closeBackendIdleConnections() {
	s.transportMu.Lock()
	var transports []*http.Transport
	for _, tr := range s.poolTransports {
		transports = append(transports, tr)
	}
	for _, tr := range s.transports {
		transports = append(transports, tr)
	}
	s.transportMu.Unlock()
	for _, tr := range transports {
		tr.CloseIdleConnections()
	}
}
