package proxy

import (
	"context"
	"testing"
	"time"
)

// TestGeneralHealthCheckDoesNotRecoverBackendForAffinity covers #2056. Affinity does
// not give a backend marked unhealthy the one-minute retry that hashing and round
// robin give it (docs/PROXY.md §6.2, §7.1): for affinity it stays unhealthy until a
// connection to it succeeds. IsBackendHealthy, which hashing and round robin call for
// other users, used to flip the shared IsHealthy flag back once the quarantine had
// passed, after which the affinity check accepted the backend too.
func TestGeneralHealthCheckDoesNotRecoverBackendForAffinity(t *testing.T) {
	const down, up = "backend1:143", "backend2:143"
	cm, err := NewConnectionManager([]string{down, up}, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	am := &MockAffinityManager{backends: map[string]string{"alice@example.com:imap": down}}
	cm.SetAffinityManager(am)

	for i := 0; i < 3; i++ {
		cm.RecordConnectionFailure(down)
	}
	if cm.IsBackendHealthyForAffinity(down) {
		t.Fatal("precondition: backend1 not marked unhealthy after 3 failures")
	}

	// Let the quarantine pass.
	cm.healthMu.Lock()
	cm.backendHealth[down].LastFailure = time.Now().Add(-backendRecoveryInterval - time.Second)
	cm.healthMu.Unlock()
	if cm.IsBackendHealthyForAffinity(down) {
		t.Fatal("precondition: affinity accepted backend1 after its quarantine, before any general health check")
	}

	// Control: hashing and round robin do give it its retry (another user's routing).
	if !cm.IsBackendHealthy(down) {
		t.Fatal("control: IsBackendHealthy did not give backend1 its retry after the quarantine")
	}

	// That retry is not a successful connection, so affinity must still refuse it.
	if cm.IsBackendHealthyForAffinity(down) {
		t.Error("IsBackendHealthyForAffinity accepts backend1 after a general health check, without a successful connection")
	}
	res, err := DetermineRoute(RouteParams{
		Ctx: context.Background(), Username: "alice@example.com", Protocol: "imap",
		ConnManager: cm, EnableAffinity: true, ProxyName: "test",
	})
	if err != nil {
		t.Fatalf("DetermineRoute: %v", err)
	}
	if res.RoutingMethod == "affinity" {
		t.Errorf("alice routed by affinity to %s, a backend marked unhealthy with no successful connection since", res.PreferredAddr)
	}
	if _, ok := am.GetBackend("alice@example.com", "imap"); ok {
		t.Error("alice's affinity to the unhealthy backend1 was not deleted")
	}

	// A successful connection is what makes it eligible for affinity again.
	cm.RecordConnectionSuccess(down)
	if !cm.IsBackendHealthyForAffinity(down) {
		t.Error("backend1 still refused for affinity after a successful connection")
	}
}
