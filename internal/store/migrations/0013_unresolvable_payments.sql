-- 669: a pending payment the resolver cannot finish gets a NAME, so an operator
-- can close it — and so nothing else can.
--
-- WHY A MARKER AND NOT A JUDGEMENT AT RENDER TIME. §6 says only the operator can
-- say whether such a payment settled, and the control that lets them say it can
-- make the ledger lie in either direction: closing as settled when it failed
-- loses money from the ledger's view, closing as failed when it settled credits
-- money that is gone. So it is fenced to rows the RESOLVER has already given up
-- on. A page that decided for itself which rows qualify would be a second
-- opinion about that, and an operator racing the recon loop — asserting an
-- outcome for a row the node is about to answer for — is a worse failure than
-- the stranded row this control exists to clear.
--
-- ADD COLUMN, twice, and no rebuild: `txns` is referenced by `balance_entries`,
-- and rebuilding it is what BrollyZap-dsi cost. Neither column needs a
-- constraint change, so neither needs one.

-- resolve_attempts counts consecutive failed resolution passes.
--
-- The GENERAL case, not one error's. `hdu` fixed the fee overspend that could
-- never succeed; what made it costly was that a persistent Settle failure had no
-- terminal disposition at all, so it recurred every start for ever. Any
-- persistent failure now walks a counter, and at the bound the row is named for
-- the operator instead of being retried again. A transient one — a node that is
-- down — resets it by succeeding.
ALTER TABLE txns ADD COLUMN resolve_attempts INTEGER NOT NULL DEFAULT 0;

-- unresolvable_reason is the resolver's own words for why it gave up, and its
-- presence is what unlocks the operator's control.
--
-- NULL means "the resolver still owns this row". That is the load-bearing state:
-- everything an operator may do to a pending payment is gated on this column
-- being non-NULL, so the gate is one predicate in one place rather than a rule
-- the page and the handler each remember.
ALTER TABLE txns ADD COLUMN unresolvable_reason TEXT;
