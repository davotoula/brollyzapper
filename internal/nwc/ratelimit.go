package nwc

import (
	"sync"
	"time"
)

// requestLimit is one pairing's token bucket (l3j). See RequestsPerMinute for the
// numbers and handle for where it is consulted.
//
// IN MEMORY, PER PROCESS, and a restart refills it. That is correct for a limiter
// whose job is RATE: a restart costs longer than a burst refills, so nothing is
// gained by persisting it, and every request would pay a row write for it — the
// write this bead exists to bound. QUOTA, which must survive a restart, is the
// wallet's and the connection budget's, not this.
//
// On the connection rather than in a map on the Service, so it lives and dies with
// the pairing: a revoked connection's bucket goes with it, and a reload keeps the
// same *connection and therefore the same bucket (update swaps only the row).
//
// The zero value is a FULL bucket: a pairing's first requests are its burst.
//
// Not internal/api's limiter: nwc sits below api in internal/arch's layer order,
// and that one counts HTTP callers in fixed windows with nothing to say about a
// request delivered once per relay or about refusal episodes.
type requestLimit struct {
	mu sync.Mutex
	// tokens is a float because the refill is continuous; this is a count of
	// requests, never money, so §4's integer rule does not reach it.
	tokens float64
	last   time.Time
	// refusing is whether this pairing is inside a refusal EPISODE — see admit.
	refusing bool

	// admitted is a ring of the ids this bucket charged recently, so a SIBLING
	// relay's copy of one request is not charged again. See admit.
	admitted [admittedMemory]admission
	next     int
}

type admission struct {
	id string
	at time.Time
}

// admittedMemory is how many recent admissions the sibling check can see.
//
// Every id admitted within SiblingDeliveryWindow must still be in the ring, or a
// late sibling copy is charged. The most a bucket can admit inside that window is
// its whole burst plus what refills during it — so the ring is sized from the
// same constants, and moves with them. One spare for the boundary.
const admittedMemory = RequestBurst + int(SiblingDeliveryWindow/(time.Minute/RequestsPerMinute)) + 1

// admit charges one request against the bucket, and reports whether it may be
// served and — when it may not — whether this refusal STARTS an episode.
//
// A SIBLING COPY IS FREE. A pairing names up to three relays and one request
// arrives once per relay within milliseconds (d24.18). Charged per copy, the last
// token goes to one relay's copy and the next copy is answered RATE_LIMITED onto
// the same relays the winner publishes the real answer to — d24.18's inconsistent
// answers, reintroduced by the limiter. So an id this bucket admitted within
// SiblingDeliveryWindow passes without a token and goes on to the claim, which
// dedupes it and executes nothing. The window is what stops this being a way
// around the bucket: the same event re-sent later is a client asking again, and it
// pays.
//
// A copy of a REFUSED request is not remembered and is refused again — the same
// answer on every relay, which is the property that matters.
//
// THE EPISODE is what keeps a flood from becoming a flood of audit rows and log
// lines. It starts at the first refusal and ends only when the bucket is FULL
// again, i.e. the client has been quiet for a whole burst's worth of refill. Not
// at the next admitted request: under a sustained flood a token refills every
// second, one request is served, and "ends at the next success" would open a new
// episode — and write a new row — once a second.
func (l *requestLimit) admit(id string, now time.Time) (ok, episodeStarts bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// A clock that stepped backwards refills nothing rather than draining. And
	// the FIRST call refills to full: last is the zero time, so elapsed is
	// enormous and the min is the burst — which is what makes the zero value a
	// full bucket without a flag saying so.
	if elapsed := now.Sub(l.last); elapsed > 0 {
		l.tokens = min(float64(RequestBurst), l.tokens+elapsed.Minutes()*RequestsPerMinute)
		l.last = now
	}
	if l.tokens >= RequestBurst {
		l.refusing = false
	}

	for _, a := range l.admitted {
		if a.id == id && now.Sub(a.at) < SiblingDeliveryWindow {
			return true, false
		}
	}

	if l.tokens >= 1 {
		l.tokens--
		l.admitted[l.next] = admission{id: id, at: now}
		l.next = (l.next + 1) % len(l.admitted)
		return true, false
	}
	starts := !l.refusing
	l.refusing = true
	return false, starts
}
