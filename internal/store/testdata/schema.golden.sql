CREATE INDEX idx_audit_created ON audit_events(created_at DESC);
CREATE UNIQUE INDEX idx_audit_source ON audit_events(source_id) WHERE source_id IS NOT NULL;
CREATE INDEX idx_entries_txn ON balance_entries(txn_id);
CREATE INDEX idx_handled_at ON nwc_handled_requests(handled_at);
CREATE INDEX idx_invoices_open_expiry ON invoices(state, expires_at)
WHERE state = 'open';
CREATE INDEX idx_pending_receipts_due ON pending_zap_receipts(next_attempt_at);
CREATE INDEX idx_txns_created ON txns(created_at DESC);
CREATE UNIQUE INDEX idx_txns_invoice_hash ON txns(payment_hash) WHERE kind = 'invoice_in';
CREATE INDEX idx_txns_pending_out ON txns(created_at, id, payment_hash)
  WHERE kind = 'payment_out' AND state = 'pending';
CREATE UNIQUE INDEX idx_txns_pending_out_hash ON txns(payment_hash)
  WHERE kind = 'payment_out' AND state = 'pending';
CREATE TABLE audit_events (
  id         INTEGER PRIMARY KEY,
  event      TEXT NOT NULL,   -- auth.ok | auth.fail | macaroon.bake | macaroon.revoke
                              -- | macaroon.rotate | connection.create | connection.revoke
                              -- | sending.toggle | setting.change | domain.probe
                              -- | guard.reject | guard.register
  severity   TEXT NOT NULL,   -- info | warn | error
  detail     TEXT,            -- JSON, redacted by the same LogValue rules
  remote     TEXT,            -- source IP for auth events, else NULL
  created_at INTEGER NOT NULL
, source_id TEXT);
CREATE TABLE balance_entries (
  id          INTEGER PRIMARY KEY,
  txn_id      INTEGER NOT NULL REFERENCES txns(id),
  amount_msat INTEGER NOT NULL,      -- signed
  reason      TEXT NOT NULL,         -- allocate | deallocate | credit | reserve
                                     -- | refund_reserve | reverse | adjust
  created_at  INTEGER NOT NULL
);
CREATE TABLE invoices (
  payment_hash     TEXT PRIMARY KEY,
  amount_msat      INTEGER NOT NULL,
  description_hash TEXT NOT NULL,
  bolt11           TEXT NOT NULL,
  zap_request      TEXT,             -- raw JSON, byte-identical to what was received
  zap_relays       TEXT,             -- JSON array from the zap request's relays tag
  state            TEXT NOT NULL,    -- open | settled | expired
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL
, comment TEXT);
CREATE TABLE "nwc_connections" (
  id               INTEGER PRIMARY KEY,
  name             TEXT NOT NULL,
  service_privkey  TEXT NOT NULL,    -- unique per connection (NIP-47 privacy guidance)
  service_pubkey   TEXT NOT NULL UNIQUE,
  client_pubkey    TEXT NOT NULL,
  client_secret    TEXT NOT NULL,    -- so the URI can be re-displayed by the operator
  -- The pairing's relays, as a JSON array, in the order the URI named them.
  -- NIP-47: "URL of the relay where the wallet service is connected and will be
  -- listening for events. May be more than one." Never default_relays and never
  -- a setting — see §8, and the internal/arch rule that polices it.
  relays           TEXT NOT NULL DEFAULT '[]',
  permissions      TEXT NOT NULL,    -- JSON array of permission GROUPS (§8)
  budget_msat      INTEGER,          -- NULL = unlimited (still bounded by the ceiling)
  budget_period    TEXT,             -- daily | weekly | monthly | never
  budget_used_msat INTEGER NOT NULL DEFAULT 0,
  budget_renews_at INTEGER,
  max_payment_msat INTEGER,
  created_at       INTEGER NOT NULL,
  last_used_at     INTEGER,
  revoked          INTEGER NOT NULL DEFAULT 0,
  last_refusal_code    TEXT NOT NULL DEFAULT '',
  last_refusal_message TEXT NOT NULL DEFAULT '',
  last_refusal_at      INTEGER
, panic_count INTEGER NOT NULL DEFAULT 0, paused_reason TEXT NOT NULL DEFAULT '', paused_at INTEGER);
CREATE TABLE nwc_handled_requests (
  event_id      TEXT PRIMARY KEY,      -- the kind 23194 event id
  connection_id INTEGER NOT NULL REFERENCES nwc_connections(id),
  method        TEXT NOT NULL,
  response_json TEXT NOT NULL,         -- plaintext response, re-encrypted on replay
  handled_at    INTEGER NOT NULL
);
CREATE TABLE pending_zap_receipts (
  payment_hash     TEXT PRIMARY KEY REFERENCES invoices(payment_hash),
  attempts         INTEGER NOT NULL DEFAULT 0,
  -- The wall-clock deadline for giving up, computed once from the first
  -- attempt. Stored rather than derived so a change to the retry window cannot
  -- silently extend the life of rows already queued.
  give_up_at       INTEGER NOT NULL,
  next_attempt_at  INTEGER NOT NULL,
  last_error       TEXT
);
CREATE TABLE schema_migrations (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  applied_at INTEGER NOT NULL
);
CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE "txns" (
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
, dispatched_at INTEGER, resolve_attempts INTEGER NOT NULL DEFAULT 0, unresolvable_reason TEXT, out_metadata TEXT, out_description_hash TEXT);
