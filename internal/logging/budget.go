package logging

import (
	"sync"
	"time"
)

// DefaultRefusalsPerHour is how many of one remote-triggerable refusal reach
// §12's durable trail in an hour.
//
// Twenty, and it is one number where there were three. `internal/nostr` and
// `internal/nwc` each grew their own constant with the same justification
// written out twice, and the two writers that had none — abandoned zap receipts
// and the guard's rejections — were unbounded because nothing said they should
// not be. That is a rule with an exemption nobody decided, which is a named
// failure shape in this project.
//
// WHY A BOUND AT ALL. The trail is a fixed ring: §12 trims to 10 000 rows,
// oldest first, and the guard's own relay ring is 32. Every one of these events
// can be driven by somebody who is not the operator — a relay that refuses every
// dial, a paired client retrying a revoked credential, a stranger paying zaps
// while the relays are down, a compromised server hammering the guard's socket —
// so an unbounded writer lets a stranger evict `macaroon.bake`, which is the row
// an operator most needs after an incident.
//
// WHY TWENTY. An episode's first rows carry the whole story: which relay, which
// connection, which method, when it started. The hundredth adds nothing an
// operator acts on differently, and it costs a row that recorded something else.
//
// EXPIRY CONDITION: if a caller needs a different number, it says why beside its
// own constant rather than moving this one — and the arch rule that classifies
// audit writers is what will make that visible.
const DefaultRefusalsPerHour = 20

// RefusalBudget bounds one kind of event to a number per rolling hour.
//
// It is deliberately NOT an Auditor: the guard has no database mount (§16) and
// writes to its own relayed ring, so a bound tied to the Auditor could not cover
// the writer that most needs one. This is the counting, and nothing else.
//
// The zero value is not usable; call NewRefusalBudget.
type RefusalBudget struct {
	mu          sync.Mutex
	limit       int
	now         func() time.Time
	windowStart time.Time
	used        int
	// announced records that this window has already said it is bounded, so the
	// "further ones are logged only" row is written once and not per refusal.
	announced bool
}

// NewRefusalBudget bounds to limit events per hour. A limit of zero or less
// takes DefaultRefusalsPerHour; now may be nil, and takes time.Now.
func NewRefusalBudget(limit int, now func() time.Time) *RefusalBudget {
	if limit <= 0 {
		limit = DefaultRefusalsPerHour
	}
	if now == nil {
		now = time.Now
	}
	return &RefusalBudget{limit: limit, now: now}
}

// Allow reports whether this event may be recorded durably, and — when it may
// not — whether this is the FIRST one past the bound in this window.
//
// THE SECOND ANSWER IS THE POINT, and it is what the three hand-rolled counters
// did not have. A bound that silently stops writing leaves an operator unable to
// tell "bounded" from "nothing happened", which is the difference between a
// quiet hour and a flood being hidden from them. The caller writes ONE row
// saying the bound was reached, and then goes quiet until the window rolls.
//
// Every refusal is still logged by its caller either way. What the bound
// declines to do is spend the durable trail on repetition.
func (b *RefusalBudget) Allow() (record bool, sayBounded bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if now.Sub(b.windowStart) >= time.Hour {
		b.windowStart, b.used, b.announced = now, 0, false
	}
	if b.used < b.limit {
		b.used++
		return true, false
	}
	if !b.announced {
		b.announced = true
		return false, true
	}
	return false, false
}
