package server

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/logger"
)

const (
	// gossipDedupWindow is how long an applied gossip event ID is remembered.
	// memberlist keeps handing a queued broadcast out until its transmit budget
	// is spent, which takes a few gossip intervals, so this is orders of
	// magnitude longer than a duplicate can be in flight.
	gossipDedupWindow = 60 * time.Second

	// gossipHeartbeatInterval is how often an instance re-asserts that it is
	// alive. A heartbeat carries no counts, so its size does not grow with the
	// number of connections the instance holds.
	gossipHeartbeatInterval = 30 * time.Second

	// staleInstanceThreshold is how long the counts of another instance survive
	// without a heartbeat before peers retire them: ten missed heartbeats.
	staleInstanceThreshold = 5 * time.Minute

	// staleEventThreshold is how old gossiped information may be before it is
	// treated as a replay from a healed partition rather than as news.
	staleEventThreshold = 5 * time.Minute

	// maxHeartbeatQueued bounds the heartbeat tier. memberlist only asks for
	// broadcasts once it has a gossip target, so on a node whose peers are all
	// unreachable nothing drains the queue while heartbeats keep arriving. A
	// heartbeat is superseded by the next one, so keeping the newest is enough.
	maxHeartbeatQueued = 2

	// defaultTombstoneEntries caps a tombstone map whose owner did not give it
	// the cap of the map it shadows.
	defaultTombstoneEntries = 50000

	// maxDedupEntries caps the ledger of applied event IDs. It shadows no map
	// of ours - an ID is minted per event, and the auth-failure events that
	// carry them arrive at whatever rate someone is hammering the cluster with
	// - so it is bounded by count alone. Forgetting an ID early only re-exposes
	// the duplicate application it was there to suppress.
	maxDedupEntries = 50000

	// maxDeferredHeld caps the ledger of decrements waiting for the increment
	// they cancel, counting the decrements rather than the keys they are filed
	// under: a key whose unmatched decrements keep arriving has its arrival
	// time refreshed each time and so never ages out. Reordered pairs in flight
	// at one instant are a small fraction of the connections a proxy holds, so
	// reaching this means a peer is sending decrements whose increments are
	// never coming, and what a refused decrement costs is the phantom count the
	// ledger would have prevented, which the next push/pull repairs.
	maxDeferredHeld = 10000

	// maxCriticalQueued bounds the kick tier, which nothing else drains on a
	// node whose peers are all unreachable. A kick must not be dropped, so the
	// cap is set where the two requirements stop competing: reaching it takes
	// either a partition long enough that the oldest queued kicks are already
	// past the staleness threshold receivers apply at the door, or a sustained
	// rate of kicks no operator workflow produces. Each kick was in any case
	// delivered to every reachable member over TCP when it was issued; the
	// queued copy is the backstop for peers that were not reachable then.
	//
	// Which kick is discarded at the cap is not chosen by age. In exactly the
	// case the cap exists for nothing has been transmitted, so memberlist's
	// ordering falls through to message length and the shortest queued kick -
	// the one for the shortest username - goes first, whatever its age. Picking
	// by length is not what one would choose, but nothing in this queue can
	// express another order, and the bound is worth more than the choice.
	maxCriticalQueued = 10000
)

// gossipBroadcast is one encoded event on the gossip bus. Events are never
// superseded - a register and an unregister for the same user both have to be
// applied - so nothing invalidates anything, and the marker interface keeps
// memberlist from scanning the whole queue on every enqueue.
//
// DELIVERY ORDER IS NOT PRESERVED. memberlist's queue hands out, within a
// transmit tier, the largest message that still fits the datagram and breaks
// ties by newest id, so two events queued back to back are routinely
// transmitted in the opposite order and a peer applies them that way. Every
// handler on this bus must therefore converge to the same state whichever order
// a pair of related events arrives in: removals are guarded by gossipTombstones
// and counter events by deferredDecrements.
type gossipBroadcast []byte

func (b gossipBroadcast) Invalidates(memberlist.Broadcast) bool { return false }
func (b gossipBroadcast) Message() []byte                       { return b }
func (b gossipBroadcast) Finished()                             {}
func (b gossipBroadcast) UniqueBroadcast()                      {}

// gossipQueue is the outbound side of every gossip source in this package:
// memberlist's own TransmitLimitedQueue, which retransmits a message until it
// has reached the cluster and then retires it.
//
// Messages are encoded by the caller and enqueued ready to send, because
// memberlist asks for broadcasts once per gossip target - about fifteen times a
// second - and must never pay for re-encoding a backlog.
type gossipQueue struct {
	kind       string
	queue      *memberlist.TransmitLimitedQueue
	maxQueued  int // 0 = never pruned
	maxMsgSize int

	// critical marks a queue whose messages nothing else repairs - a kick - so
	// that an overflow is reported as an error rather than as the routine
	// backpressure the ordinary queue sees.
	critical bool

	pruned    atomic.Uint64
	oversized atomic.Uint64
}

// gossipDropLogInterval keeps a queue that overflows on every enqueue - the
// case worth knowing about - from filling the log with one line per event.
const gossipDropLogInterval = 1000

// newGossipQueue creates a queue bounded to maxQueued messages. maxQueued of 0
// means the queue is never pruned, which is only safe for a queue whose input
// rate is bounded by something else. clusterMgr may be nil (local mode), in
// which case the queue works but nothing ever drains it.
func newGossipQueue(kind string, clusterMgr *cluster.Manager, maxQueued int) *gossipQueue {
	return &gossipQueue{
		kind: kind,
		queue: &memberlist.TransmitLimitedQueue{
			NumNodes:       clusterMgr.GetMemberCount,
			RetransmitMult: clusterMgr.RetransmitMult(),
		},
		maxQueued:  maxQueued,
		maxMsgSize: clusterMgr.MaxBroadcastSize(),
	}
}

// newCriticalGossipQueue creates the queue for messages nothing else repairs.
// Its cap exists only so that a node whose peers are all unreachable cannot
// grow it without limit, so reaching it is an error rather than backpressure.
func newCriticalGossipQueue(kind string, clusterMgr *cluster.Manager, maxQueued int) *gossipQueue {
	q := newGossipQueue(kind, clusterMgr, maxQueued)
	q.critical = true
	return q
}

// enqueue queues an already-encoded message and reports whether it was accepted.
func (g *gossipQueue) enqueue(msg []byte) bool {
	if len(msg) > g.maxMsgSize {
		if total := g.oversized.Add(1); total%gossipDropLogInterval == 1 {
			logger.Warn("Gossip: Dropping oversized broadcast", "kind", g.kind,
				"size", len(msg), "max", g.maxMsgSize, "dropped_total", total)
		}
		return false
	}

	g.queue.QueueBroadcast(gossipBroadcast(msg))

	// Prune discards from the end of memberlist's own ordering: the
	// most-transmitted messages first, and among messages transmitted equally
	// often the shortest, with age breaking only that last tie. A queue that
	// overflows because nothing is being transmitted therefore loses its
	// shortest message rather than its oldest.
	if g.maxQueued > 0 && g.queue.NumQueued() > g.maxQueued {
		g.queue.Prune(g.maxQueued)
		if total := g.pruned.Add(1); total%gossipDropLogInterval == 1 {
			log := logger.Warn
			if g.critical {
				log = logger.Error
			}
			log("Gossip: Broadcast queue full - dropping queued messages",
				"kind", g.kind, "max", g.maxQueued, "dropped_total", total)
		}
	}

	return true
}

// GetBroadcasts hands memberlist the messages that fit the datagram budget.
func (g *gossipQueue) GetBroadcasts(overhead, limit int) [][]byte {
	return g.queue.GetBroadcasts(overhead, limit)
}

// numQueued returns how many messages still owe the cluster a transmission.
func (g *gossipQueue) numQueued() int {
	return g.queue.NumQueued()
}

// drainTiers answers memberlist from three queues in priority order.
//
// The heartbeat goes first and needs no share of its own: its queue holds at
// most maxHeartbeatQueued tiny messages, so it can never take a meaningful part
// of the datagram. It cannot share a tier with anything else either - within a
// transmit tier memberlist hands out the largest message that fits, and a
// heartbeat is the smallest message a tracker produces, so a backlog of any
// kind would delay it round after round, precisely while peers most need proof
// this instance is alive.
//
// The critical tier is capped at half of what remains, so a burst of kicks
// cannot take a whole datagram and hold ordinary events off the wire; if half
// cannot carry a single critical message the whole remainder is offered so that
// one always gets out. critical may be nil for sources that have no such tier.
func drainTiers(heartbeat, critical, ordinary *gossipQueue, overhead, limit int) [][]byte {
	msgs := heartbeat.GetBroadcasts(overhead, limit)
	used := wireBytes(msgs, overhead)

	if critical != nil {
		remaining := limit - used
		criticalMsgs := critical.GetBroadcasts(overhead, remaining/2)
		if len(criticalMsgs) == 0 {
			criticalMsgs = critical.GetBroadcasts(overhead, remaining)
		}
		used += wireBytes(criticalMsgs, overhead)
		msgs = append(msgs, criticalMsgs...)
	}

	return append(msgs, ordinary.GetBroadcasts(overhead, limit-used)...)
}

// wireBytes is what the given messages occupy of the datagram budget.
func wireBytes(msgs [][]byte, overhead int) int {
	total := 0
	for _, msg := range msgs {
		total += overhead + len(msg)
	}
	return total
}

// gossipDedup suppresses duplicate delivery of gossip events. memberlist asks
// for broadcasts once per gossip target and may pick the same peer again while
// a message is still queued, so delivery is at-least-once. Events that are not
// idempotent - a connection register, an authentication failure - must only be
// applied for the first copy. The zero value is ready for use.
//
// IDs are held in two generations that rotate once per window, which keeps the
// packet path free of scans. The window alone bounds nothing - two windows hold
// however many events the cluster produces in that time - so a generation is
// also rotated early once it reaches half of maxDedupEntries.
type gossipDedup struct {
	mu       sync.Mutex
	current  map[string]struct{}
	previous map[string]struct{}
	rotated  time.Time
}

// seenBefore records an event ID and reports whether it was already applied.
// Events without an ID (nodes running an older build) are always applied.
func (d *gossipDedup) seenBefore(eventID string) bool {
	if eventID == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if now.Sub(d.rotated) > gossipDedupWindow {
		d.rotateNowLocked(now)
	}

	if _, exists := d.current[eventID]; exists {
		return true
	}
	if _, exists := d.previous[eventID]; exists {
		return true
	}

	if d.current == nil {
		d.current = make(map[string]struct{})
	}
	d.current[eventID] = struct{}{}

	if len(d.current) >= (maxDedupEntries+1)/2 {
		d.rotateNowLocked(now)
	}
	return false
}

func (d *gossipDedup) rotateNowLocked(now time.Time) {
	d.previous = d.current
	d.current = nil
	d.rotated = now
}

// gossipTombstones records, per key, when the state behind that key was last
// removed. Gossip delivery is unordered, so a removal can arrive before the
// event it removes; consulting the tombstone lets the later-delivered older
// event be recognised and ignored, which is what makes a remove/add pair
// converge to the same state whichever way round it is applied.
//
// IDs are held in two generations that rotate once per window, as in
// gossipDedup. The window is the staleness cutoff every handler applies at the
// door, so a tombstone is only ever forgotten once no event it could suppress
// would be accepted anyway. The zero value is ready for use.
//
// A tombstone is marked for every removal, including the ones that removed
// nothing here - that is the whole point, since the event it suppresses may
// still be in flight - so the map is driven by the cluster's event rate and
// needs a cap of its own. maxEntries bounds both generations together; keys are
// forgotten early once it is reached, which only re-exposes the reordering the
// tombstone would have suppressed.
type gossipTombstones struct {
	mu         sync.Mutex
	maxEntries int
	current    map[string]time.Time
	previous   map[string]time.Time
	rotated    time.Time
}

// mark records that key was removed at time at.
func (g *gossipTombstones) mark(key string, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.rotateLocked()

	if existing, ok := g.current[key]; ok && existing.After(at) {
		return
	}
	if g.current == nil {
		g.current = make(map[string]time.Time)
	}
	g.current[key] = at

	maxEntries := g.maxEntries
	if maxEntries <= 0 {
		maxEntries = defaultTombstoneEntries
	}
	if len(g.current) >= (maxEntries+1)/2 {
		g.rotateNowLocked()
	}
}

// removedSince reports whether a removal at or after at has already been
// applied for key, that is, whether an event stamped at is superseded.
func (g *gossipTombstones) removedSince(key string, at time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.rotateLocked()

	removed, ok := g.current[key]
	if previous, okPrevious := g.previous[key]; okPrevious && (!ok || previous.After(removed)) {
		removed, ok = previous, true
	}
	return ok && !at.After(removed)
}

func (g *gossipTombstones) rotateLocked() {
	if time.Since(g.rotated) <= staleEventThreshold {
		return
	}
	g.rotateNowLocked()
}

func (g *gossipTombstones) rotateNowLocked() {
	g.previous = g.current
	g.current = nil
	g.rotated = time.Now()
}

// deferredDecrements holds a decrement whose matching increment has not been
// delivered yet. Clamping the counter at zero and then applying the increment
// would leave a phantom connection counted against the per-user and per-IP
// limits until push/pull happened to repair it.
//
// Both events of a pair are produced by the same instance, so their timestamps
// come from one clock and are directly comparable: a held decrement cancels an
// increment stamped no later than itself, while a genuinely newer increment is
// applied as usual. Callers serialise access through the tracker's own lock.
//
// What is held is bounded by maxDeferredHeld, which pruning cannot do on its
// own: age is measured from local arrival and refreshed by each new decrement
// for the key, so a key that keeps receiving them never ages out.
type deferredDecrements struct {
	kind    string // names the owner in the log when the ledger is full
	held    map[string]deferredDecrement
	total   int
	refused uint64
}

type deferredDecrement struct {
	count int
	at    time.Time // newest decrement being held for this key, by the sender's clock
	since time.Time // when the newest of them arrived here, by this node's clock
}

// hold records a decrement that had nothing to subtract from.
func (d *deferredDecrements) hold(key string, at time.Time) {
	if d.total >= maxDeferredHeld {
		d.refused++
		if d.refused%gossipDropLogInterval == 1 {
			logger.Warn("Gossip: Deferred decrement ledger full - refusing to hold",
				"kind", d.kind, "max", maxDeferredHeld, "refused_total", d.refused)
		}
		return
	}

	if d.held == nil {
		d.held = make(map[string]deferredDecrement)
	}

	entry := d.held[key]
	entry.count++
	if at.After(entry.at) {
		entry.at = at
	}
	entry.since = time.Now()
	d.held[key] = entry
	d.total++
}

// consume reports whether an increment stamped at is the one a held decrement
// was waiting for, and takes that decrement out of the ledger if so.
func (d *deferredDecrements) consume(key string, at time.Time) bool {
	entry, exists := d.held[key]
	if !exists || entry.count <= 0 || at.After(entry.at) {
		return false
	}

	entry.count--
	d.total--
	if entry.count == 0 {
		delete(d.held, key)
	} else {
		d.held[key] = entry
	}
	return true
}

// prune drops decrements held for longer than window, whose increment is never
// coming. Age is measured from local arrival: the event's own timestamp comes
// from the sender's clock, and a peer running behind ours would have its
// decrements retired the moment they were stored - leaving the increment they
// were waiting for to be applied as a phantom connection.
func (d *deferredDecrements) prune(window time.Duration) {
	cutoff := time.Now().Add(-window)
	for key, entry := range d.held {
		if entry.since.Before(cutoff) {
			d.total -= entry.count
			delete(d.held, key)
		}
	}
}
