package cluster

import (
	"strings"
	"testing"
)

// saturatingBroadcaster always has more messages than a datagram can carry, so
// whichever subsystem is asked first fills the budget on its own.
func saturatingBroadcaster(payload byte, sent *int) func(int, int) [][]byte {
	return func(overhead, limit int) [][]byte {
		msg := make([]byte, 600)
		for i := range msg {
			msg[i] = payload
		}

		var msgs [][]byte
		used := 0
		for i := 0; i < 100; i++ {
			if used+overhead+len(msg) > limit {
				break
			}
			msgs = append(msgs, msg)
			used += overhead + len(msg)
			*sent++
		}
		return msgs
	}
}

// TestDelegateGetBroadcastsDoesNotStarveSubsystems asserts that a saturated
// subsystem cannot hold the datagram budget indefinitely. A datagram fits only
// a couple of messages, and memberlist calls the delegate about fifteen times a
// second, so with a fixed collector order the last subsystem would never gossip
// and its events would age past the receivers' staleness cutoff.
func TestDelegateGetBroadcastsDoesNotStarveSubsystems(t *testing.T) {
	m := &Manager{nodeID: "node-1"}
	d := &clusterDelegate{meta: []byte("node-1"), manager: m}

	var rateLimit, affinity, connection, ipLimit int
	m.RegisterRateLimitBroadcaster(saturatingBroadcaster('R', &rateLimit))
	m.RegisterAffinityBroadcaster(saturatingBroadcaster('A', &affinity))
	m.RegisterConnectionBroadcaster(saturatingBroadcaster('C', &connection))
	m.RegisterIPLimitBroadcaster(saturatingBroadcaster('I', &ipLimit))

	// One second of gossip: GossipInterval 200ms x GossipNodes 3.
	for i := 0; i < 15; i++ {
		d.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit)
	}

	counts := map[string]int{
		"rate-limit": rateLimit,
		"affinity":   affinity,
		"connection": connection,
		"ip-limit":   ipLimit,
	}
	for kind, sent := range counts {
		if sent == 0 {
			t.Errorf("%s gossiped nothing in 15 calls while another subsystem was saturated: %v", kind, counts)
		}
	}
	t.Logf("messages taken per subsystem over 15 calls: %v", counts)
}

// TestStateProvidersDispatchByKindNotName covers deployments with more than one
// listener per protocol. Two nodes name their listeners independently, and the
// order in which their providers register is not stable, so push/pull cannot
// match a payload to a provider by name. It matches by kind instead, and every
// provider of that kind sees the payload and decides for itself.
func TestStateProvidersDispatchByKindNotName(t *testing.T) {
	sender := &Manager{nodeID: "node-1"}
	sender.RegisterStateProvider(StateKindConnection, "node-1-imap-a",
		func() []byte { return []byte("state-a") },
		func([]byte) { t.Error("the sender merged its own state") },
	)
	sender.RegisterStateProvider(StateKindConnection, "node-1-imap-b",
		func() []byte { return []byte("state-b") },
		func([]byte) { t.Error("the sender merged its own state") },
	)

	// The receiver's listeners carry entirely different names, and one is of
	// another kind and must not be handed connection state.
	receiver := &Manager{nodeID: "node-2"}
	merged := make(chan string, 8)
	receiver.RegisterStateProvider(StateKindConnection, "node-2-imap-x",
		func() []byte { return nil },
		func(b []byte) { merged <- "x:" + string(b) },
	)
	receiver.RegisterStateProvider(StateKindConnection, "node-2-imap-y",
		func() []byte { return nil },
		func(b []byte) { merged <- "y:" + string(b) },
	)
	receiver.RegisterStateProvider(StateKindIPLimit, "node-2-imap-x",
		func() []byte { return nil },
		func(b []byte) { merged <- "ip:" + string(b) },
	)

	receiver.mergeRemoteState(sender.localState())
	close(merged)

	got := make(map[string]bool)
	for entry := range merged {
		got[entry] = true
	}

	for _, want := range []string{"x:state-a", "x:state-b", "y:state-a", "y:state-b"} {
		if !got[want] {
			t.Errorf("connection provider did not receive %q: got %v", want, got)
		}
	}
	for entry := range got {
		if strings.HasPrefix(entry, "ip:") {
			t.Errorf("a provider of another kind was handed connection state: %q", entry)
		}
	}
}

// TestStateProvidersSurviveDuplicateNames keeps the older guarantee: two
// providers of the same kind registered under the same name both stay in the
// exchange. The name is node-local now, so a suffix costs nothing.
func TestStateProvidersSurviveDuplicateNames(t *testing.T) {
	m := &Manager{nodeID: "node-1"}

	m.RegisterStateProvider(StateKindConnection, "same",
		func() []byte { return []byte("first") },
		func([]byte) {},
	)
	m.RegisterStateProvider(StateKindConnection, "same",
		func() []byte { return []byte("second") },
		func([]byte) {},
	)

	if got := len(m.snapshotStateProviders()); got != 2 {
		t.Fatalf("registered 2 providers under the same name, %d survived", got)
	}
}
