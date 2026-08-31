-- utt: the payment_hash uniqueness was for INBOUND rows, and applying it to the
-- whole table poisoned every invoice whose first payment attempt failed.
--
-- §6 wants settlement idempotency: LND re-delivers a settlement after a
-- reconnect, and the guarantee that a replay is a no-op comes from the UNIQUE
-- on payment_hash in the crediting transaction, not from the stream loop. That
-- is a statement about `invoice_in` rows.
--
-- Outbound rows never needed it. The resolver looks a payment up by id and
-- state, never by hash. But d24.2 began recording payment_hash on payment_out
-- rows at reserve time — it is the only thing TrackPaymentV2 can be asked about
-- after a crash — and the table-wide constraint then meant a REVERSED payment
-- kept the hash for ever. Retrying that invoice is normal NWC client behaviour
-- and LND permits it; this schema did not.
--
-- The self-payment case changes meaning with it, deliberately: an outbound row
-- for a hash we also hold as `invoice_in` now inserts cleanly. Acceptable — LND
-- refuses self-payments itself, so the reservation simply reverses like any
-- other failure, which is a better answer than an opaque insert error.
--
-- SQLite cannot drop a column constraint in place, so this is a table rebuild,
-- and balance_entries references txns(id).
--
-- SQLite's own procedure for this requires `PRAGMA foreign_keys = OFF`, which is
-- a no-op inside a transaction — where every migration otherwise runs. So this
-- migration asks the runner for the connection-level pragma, and the runner
-- runs `PRAGMA foreign_key_check` inside the transaction before committing, so
-- a rebuild that orphaned a row rolls back rather than shipping.
--
-- `defer_foreign_keys` was tried first and is NOT a substitute: dropping the
-- parent records a deferred violation per child row, and recreating it does not
-- retract them — they are counted again at COMMIT. That version passed every
-- unit test, all of which open an EMPTY database where the copy has nothing to
-- violate, and failed on the regtest stack's first start against a real ledger.
-- migrate_txns_rebuild_internal_test.go is the test that exists so it cannot
-- happen again.
--
-- The column definitions are copied VERBATIM from 0001 and 0006 apart from the
-- one that changes. A rebuild is a rename in disguise, and the README's rule
-- about migrations carrying stale values applies to defaults too: a DEFAULT
-- retyped from memory here would silently become the schema.
-- +brollyzapper:rebuild-with-foreign-keys-off

CREATE TABLE txns_rebuilt (
  id                INTEGER PRIMARY KEY,
  kind              TEXT NOT NULL,   -- allocation | deallocation | invoice_in
                                     -- | payment_out | adjustment
  state             TEXT NOT NULL,   -- pending | settled | failed | expired
  amount_msat       INTEGER NOT NULL,          -- always positive
  fee_msat          INTEGER NOT NULL DEFAULT 0,
  fee_reserved_msat INTEGER NOT NULL DEFAULT 0,
  payment_hash      TEXT,            -- unique for invoice_in only; see below
  bolt11            TEXT,
  preimage          TEXT,
  description       TEXT,
  zap_request       TEXT,            -- raw JSON exactly as received, or NULL
  zap_receipt_id    TEXT,            -- event id of the published kind 9735
  nwc_connection_id INTEGER REFERENCES nwc_connections(id),
  note              TEXT,            -- operator reason, for allocation/adjustment
  created_at        INTEGER NOT NULL,
  settled_at        INTEGER,
  comment           TEXT             -- LUD-12, added by 0006
);

INSERT INTO txns_rebuilt
  (id, kind, state, amount_msat, fee_msat, fee_reserved_msat, payment_hash, bolt11,
   preimage, description, zap_request, zap_receipt_id, nwc_connection_id, note,
   created_at, settled_at, comment)
SELECT
   id, kind, state, amount_msat, fee_msat, fee_reserved_msat, payment_hash, bolt11,
   preimage, description, zap_request, zap_receipt_id, nwc_connection_id, note,
   created_at, settled_at, comment
FROM txns;

DROP TABLE txns;
ALTER TABLE txns_rebuilt RENAME TO txns;

CREATE INDEX idx_txns_created ON txns(created_at DESC);

-- The constraint, scoped to what it was always for. PARTIAL, so the settlement
-- path's ON CONFLICT has to name the same predicate to bind to it — §13 says
-- assert the query plan, not the artefact, and there is a test that does.
CREATE UNIQUE INDEX idx_txns_invoice_hash ON txns(payment_hash) WHERE kind = 'invoice_in';

-- And the protection the table-wide constraint was providing ACCIDENTALLY, kept
-- deliberately: no two payments for the same invoice may be IN FLIGHT at once.
--
-- Scoping the old constraint to inbound rows would otherwise have allowed two
-- pending payment_out rows with one hash — and that costs money. The resolver
-- asks TrackPaymentV2 once per row, gets SUCCEEDED for both, and settles both:
-- the ledger is debited twice for a single payment, permanently. Reconciliation
-- does not catch it, because the wallet ends up LOWER than the node, which is
-- the safe direction and raises no shortfall.
--
-- Nothing can reach it today — payInvoice has no production caller — but §8's
-- pay_invoice is exactly the caller that makes two concurrent reservations for
-- one invoice possible.
--
-- `state = 'pending'` is what keeps utt's whole point working: ReverseSpend
-- writes 'failed' and SettleSpend writes 'settled', so a resolved row leaves
-- this index and the retry it exists to allow still inserts.
CREATE UNIQUE INDEX idx_txns_pending_out_hash ON txns(payment_hash)
  WHERE kind = 'payment_out' AND state = 'pending';

-- The freeze's own query, which runs on EVERY Reserve, and the resolver's, which
-- runs every reconciliation tick. Without this both walk the whole of history:
-- `created_at < startedAt` is every row ever written, and COUNT/EXISTS has no
-- shortcut through it. §13: the plan is asserted, not the index's existence.
-- (created_at, id, payment_hash) rather than created_at alone: it covers the
-- resolver's SELECT and its ordering as well as the freeze's EXISTS, so neither
-- has to touch the table.
CREATE INDEX idx_txns_pending_out ON txns(created_at, id, payment_hash)
  WHERE kind = 'payment_out' AND state = 'pending';
