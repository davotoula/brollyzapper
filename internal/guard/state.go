package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/davotoula/brollyzapper/internal/logging"
)

// stateFile is the guard's own store, in its own DATA_DIR.
//
// It is deliberately not the server's database. §6: if the guard consulted
// anything the server can write, a compromised server would simply write itself
// a larger spend counter, or a root key id belonging to another app.
const stateFile = "guard-state.json"

// State is what the guard remembers across restarts.
type State struct {
	// SpendRootKeyID is the root key the guard baked the spend macaroon under.
	// It lives here and nowhere else, which is why RevokeSpend takes no
	// parameter (§6, §21).
	SpendRootKeyID uint64 `json:"spend_root_key_id,omitempty"`
	// ReceiveRootKeyID is the root key the receive macaroon was baked under.
	//
	// Its own key, not LND's default 0: under 0 the only revocation is rotating
	// macaroons.db, which invalidates every other app's credentials on the box
	// too — so in practice the receive credential could not be revoked at all,
	// and a stolen copy stayed valid through Re-link and through uninstall
	// (§6, d46.26).
	ReceiveRootKeyID uint64 `json:"receive_root_key_id,omitempty"`
	// PendingRootKeyIDs are keys the guard asked the node to create and has not
	// confirmed the fate of.
	//
	// One is appended before each bake and removed when that bake records its
	// result: LND creates the key when BakeMacaroon is called, so anything
	// failing in between would otherwise leave a live key nothing has a record
	// of — and only `lncli deletemacaroonid` over SSH could ever remove it.
	//
	// A SET, not one slot (d24.1). It was a single uint64 while only the receive
	// credential was baked. Two bake paths make that lossy in two ways, and the
	// second is a hole in the kill switch: a failed receive bake's key is
	// overwritten by the next spend attempt and orphaned, and a spend bake that
	// created a key at the node before failing leaves a SPEND-CAPABLE key that
	// "Disable sending" would not revoke — RevokeSpend sweeps this set for
	// exactly that reason.
	PendingRootKeyIDs []uint64 `json:"pending_root_key_ids,omitempty"`
	// PendingRootKeyID is the single-slot form this replaced. Read on load and
	// folded into the set above; never written. Kept so an install that stopped
	// with a pending key does not lose the only record of it — which would be
	// this change causing the exact leak it exists to close.
	PendingRootKeyID uint64    `json:"pending_root_key_id,omitempty"`
	ReceiveBakedAt   time.Time `json:"receive_baked_at,omitempty"`
	SpendBakedAt     time.Time `json:"spend_baked_at,omitempty"`

	// SpendAttempts is §6's rolling 24 h window, one record per intercepted
	// payment attempt (tna.1).
	//
	// PER-ATTEMPT RECORDS rather than a running total with a reset time, because
	// the window ROLLS: a total can only be reset, and a reset hands a
	// compromised server a second full cap by waiting. Records also make the one
	// decrement §14 permits possible — an observed terminal failure removes the
	// record it made, and nothing else ever removes one early.
	//
	// In the GUARD's store, which is the whole design: a counter the server
	// could write is a counter a compromised server writes to zero (§6, §16).
	SpendAttempts []SpendAttempt `json:"spend_attempts,omitempty"`

	// RecentAudit is the guard's security events, kept here because the guard
	// writes to nothing the server owns (§16) and reported on every socket
	// response until they age out. It is a ring, not a queue: nothing drains it,
	// because the guard never learns whether the server stored one.
	RecentAudit []logging.RelayedEvent `json:"recent_audit,omitempty"`

	// SendingLatch is the OPERATOR's stored intent: may this install mint spend
	// authority at all (`06v`, Ruling 1 and Ruling 2).
	//
	// A LATCH, NOT A LEASE. The spend macaroon carries a 7-day time-before, so
	// re-bakes recur; the ceremony authorises the TRANSITION off→on, and the
	// re-bake consults this without asking again. A lease would mean weekly
	// operator action, forgotten, whose failure mode is payments stopping
	// mid-week and reading as a broken app — and what the 7-day life actually
	// buys, a stolen credential file dying on its own, a latch preserves anyway.
	//
	// IT IS NOT `GUARD_ALLOW_SENDING`, which is now a DEPLOYMENT ceiling: may
	// sending ever be enabled here at all. Both must be true to bake. The env
	// var is a hard "never" for a hardened off-Umbrel deployment; this is the
	// operator's own gate, and it is what preserves §6's receive-only default
	// now that the env var defaults to true.
	SendingLatch bool `json:"sending_latch"`

	// MaxSpendMsat and MaxPaymentMsat are §6's two caps as the OPERATOR has set
	// them. They seed from GUARD_MAX_SPEND_MSAT / GUARD_MAX_PAYMENT_MSAT and
	// may then be lowered freely and raised only by ceremony.
	//
	// STORED RATHER THAN READ FROM THE ENVIRONMENT because `06v` established
	// that the environment is not operator-reachable on umbrelOS at all: there
	// is no settings surface in any app manifest, and `exports.sh` is package
	// content that an update overwrites. Env-only caps are an unmovable limit
	// set by something the operator cannot reach, which is `06v` exactly.
	//
	// THE CAPS ARE THE LARGER EXPOSURE, not the boolean. Once sending has been
	// enabled once, a compromised server can already read spend.macaroon and
	// dial LND directly — what contains it is the `brollyguard` caveat and the
	// middleware, which is ENFORCEMENT, not secrecy. So a control that let the
	// server raise its own ceiling would harm every sending install, while the
	// latch only ever protects one that never enabled sending.
	MaxSpendMsat   int64 `json:"max_spend_msat"`
	MaxPaymentMsat int64 `json:"max_payment_msat"`

	// OperatorIntentSeeded records that the three fields above have been
	// initialised, so an install upgrading from ≤0.1.12 gets them once and a
	// deliberate `false`/`0` is never mistaken for "absent".
	//
	// A MARKER RATHER THAN POINTERS: `*bool`/`*int64` would carry the same
	// information and put a nil check at every read site, three of which are on
	// the payment path. This is read once, on load.
	OperatorIntentSeeded bool `json:"operator_intent_seeded"`

	// Authorisation is the outstanding one-time grant, if any. See
	// authorisation.go — it lives in the state file rather than beside the
	// operator-facing .txt so that the file the operator reads holds only what
	// the operator needs, and the secret half is never re-read from a file the
	// guard has already written once.
	Authorisation *Authorisation `json:"authorisation,omitempty"`
}

// maxRetainedAuditEvents bounds the ring. Nothing drains it, so this is what the
// guard can lose if the server never collects: today a bake per install or
// re-link and a rotation, which the server's five-minute poll picks up long
// before 32 accumulate.
//
// P4 changes that arithmetic. §12 calls a burst of guard rejections the
// highest-signal event in the system, and a burst is precisely what overruns an
// undrained ring — revisit this bound against the poll interval when
// guard.reject starts being raised here.
const maxRetainedAuditEvents = 32

// stateStore persists State as JSON.
//
// The mutex guards the whole read-modify-write, not the two halves separately:
// the guard serves one goroutine per socket connection, so a load() then save()
// composed by the caller is a lost update waiting to happen. P4's rolling spend
// counter is exactly that shape — check the window, then record the spend — and
// a lost update there would let two payments both pass the hard cap.
type stateStore struct {
	mu   sync.Mutex
	path string
	// seed initialises the operator's stored intent the first time this store
	// is read under a version that has it. See operatorSeed.
	seed operatorSeed
}

// operatorSeed is what an install upgrading from ≤0.1.12 gets the first time its
// state is read under this version (`06v`, Migration).
//
// §19 requires the migration to be automatic, idempotent and restart-safe, and
// applying it ON LOAD is what makes it all three: there is no moment at which
// the value exists in neither shape, and the marker means a second load is a
// no-op rather than a re-seed. It is the same technique, and the same reasoning,
// as PendingRootKeyID's fold above.
type operatorSeed struct {
	maxSpendMsat   int64
	maxPaymentMsat int64
	// spendCredentialPath is how "the operator had already enabled sending"
	// is answered for an install that predates the latch.
	//
	// TWO PIECES OF EVIDENCE, either sufficient: a recorded SpendRootKeyID, and
	// a spend macaroon on disk. Seeding the latch OFF on such an install would
	// silently revoke a working wallet on upgrade — this change causing an
	// outage — which is the one failure mode a migration must not have. The
	// converse risk is nil: an install with a live spend credential has already
	// granted a compromised server everything the latch could withhold.
	spendCredentialPath string
}

// applyTo seeds the operator's intent into a state that predates it.
//
// IT RETURNS NOTHING, deliberately. It had a "did anything change" bool that
// both call sites discarded, and a return value that reads as a signal invites
// a future caller to branch on it and write the file from inside loadLocked —
// which is the one thing the load path must not do. The write happens on the
// next update, and until then every load derives the identical answer. Found by
// review.
func (o operatorSeed) applyTo(st *State) {
	if st.OperatorIntentSeeded {
		return
	}
	// Through apply, not by assignment. It is the one write site for these three
	// (an arch rule holds it), and the reason is that a direction check is worth
	// nothing if a second writer can go round it — the seed is exactly the kind
	// of well-meaning second writer that would.
	st.apply(Change{
		Control: ControlSending,
		On:      st.SpendRootKeyID != 0 || credentialFileExists(o.spendCredentialPath),
	})
	st.apply(Change{Control: ControlSpendCap, Msat: o.maxSpendMsat})
	st.apply(Change{Control: ControlPaymentCap, Msat: o.maxPaymentMsat})
	st.OperatorIntentSeeded = true
}

// update applies mutate to the stored state and writes it back, atomically with
// respect to other callers.
func (s *stateStore) update(mutate func(*State)) error {
	return s.updateIf(func(state *State) bool {
		mutate(state)
		return true
	})
}

// updateIf is update for a caller that decides, once it has seen the state,
// whether there is anything worth writing.
//
// WHY IT EXISTS: the hard cap's refusal branches (Guard.InterceptRequest) have
// to read both caps and the window from ONE version of the state, so they run
// inside this lock — but a refusal changes nothing that has to survive a
// restart, and saveLocked is an fsync and a rename. Without this, every refused
// payment costs a synchronous disk write on a path a compromised server can
// drive as fast as the socket allows. That is precisely the flood the audit
// bound (auditRejectBound) exists to make cheap, made expensive again one layer
// down. Found by review.
//
// The one thing a refusal DOES mutate is the pruned SpendAttempts slice, and
// dropping that write is safe rather than merely cheap: every reader recomputes
// the prune from the raw records (spendWindowUsed returns `kept` at all three
// call sites), so persisting it is a file-size optimisation and never a
// correctness one. The next allowed payment writes the pruned form anyway.
func (s *stateStore) updateIf(mutate func(*State) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return err
	}
	if !mutate(&state) {
		return nil
	}
	return s.saveLocked(state)
}

func openStateStore(dataDir string, seed operatorSeed) (*stateStore, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("guard: creating %s: %w", dataDir, err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("guard: securing %s: %w", dataDir, err)
	}
	return &stateStore{path: filepath.Join(dataDir, stateFile), seed: seed}, nil
}

func (s *stateStore) load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *stateStore) loadLocked() (State, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		// A FRESH INSTALL IS SEEDED TOO, and this arm is not a formality: the
		// caps mean what they say, and zero means NOTHING MAY PASS (see
		// InterceptRequest). Returning the bare zero value here would hand every
		// new install a spend cap of zero — sending enabled, every payment
		// refused, and the number the page shows contradicting the manifest.
		fresh := State{}
		s.seed.applyTo(&fresh)
		return fresh, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("guard: reading %s: %w", s.path, err)
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return State{}, fmt.Errorf("guard: parsing %s: %w", s.path, err)
	}
	// Fold the single-slot form forward. Done on LOAD rather than by a migration
	// step so there is no moment at which the value exists in neither shape.
	if state.PendingRootKeyID != 0 {
		if !slices.Contains(state.PendingRootKeyIDs, state.PendingRootKeyID) {
			state.PendingRootKeyIDs = append(state.PendingRootKeyIDs, state.PendingRootKeyID)
		}
		state.PendingRootKeyID = 0
	}
	// And the operator's intent, on the same load-time principle (`06v`).
	s.seed.applyTo(&state)
	return state, nil
}

// sendingEnabled is d24.8's rule, said once.
//
// The guard's own store is the only authority — a compromised server would
// otherwise write itself the answer, which is the reasoning §6 gives about the
// hard cap. And it is the ROOT KEY ID rather than a flag of its own on purpose:
// a separate bool can disagree with the key, and when it does the guard either
// renews a credential it cannot revoke or refuses to renew one that works. This
// way the policy bit and the revocable thing cannot diverge.
//
// Named because `SpendRootKeyID == 0` also appears meaning something else
// entirely — credentialNeedsBaking reads `rootKeyID == 0` as "baked under LND's
// default key" — and two readings of one comparison is how the next reader gets
// it wrong.
func (s State) sendingEnabled() bool { return s.SpendRootKeyID != 0 }

func (s *stateStore) saveLocked(state State) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("guard: encoding state: %w", err)
	}
	// Same atomic write as the credential volume: this file records which root
	// key the kill switch points at, and a truncated one loses the kill switch.
	return WriteCredential(s.path, raw, 0o600)
}
