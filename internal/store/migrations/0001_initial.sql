-- The §4 data model, in full. All amounts are msat stored as INTEGER; nothing
-- in this schema may ever be REAL, FLOAT or NUMERIC.
--
-- Deliberately absent, and asserted to be absent by the tests: any macaroon
-- column, and the spend root key id. Macaroons live only in the credential
-- volume the guard writes; the root key id lives only in the guard's own store
-- (§4, §6, §21).

CREATE TABLE txns (
  id                INTEGER PRIMARY KEY,
  kind              TEXT NOT NULL,   -- allocation | deallocation | invoice_in
                                     -- | payment_out | adjustment
  state             TEXT NOT NULL,   -- pending | settled | failed | expired
  amount_msat       INTEGER NOT NULL,          -- always positive
  fee_msat          INTEGER NOT NULL DEFAULT 0,
  fee_reserved_msat INTEGER NOT NULL DEFAULT 0,
  payment_hash      TEXT UNIQUE,
  bolt11            TEXT,
  preimage          TEXT,
  description       TEXT,
  zap_request       TEXT,            -- raw JSON exactly as received, or NULL
  zap_receipt_id    TEXT,            -- event id of the published kind 9735
  nwc_connection_id INTEGER REFERENCES nwc_connections(id),
  note              TEXT,            -- operator reason, for allocation/adjustment
  created_at        INTEGER NOT NULL,
  settled_at        INTEGER
);

CREATE INDEX idx_txns_created ON txns(created_at DESC);

-- Single-entry, because there is exactly one wallet. Balance is SUM over this
-- table. Reserve/settle/reverse each append rows; nothing is ever updated in
-- place, so the history is a complete audit trail of how the balance reached
-- its current value.
CREATE TABLE balance_entries (
  id          INTEGER PRIMARY KEY,
  txn_id      INTEGER NOT NULL REFERENCES txns(id),
  amount_msat INTEGER NOT NULL,      -- signed
  reason      TEXT NOT NULL,         -- allocate | deallocate | credit | reserve
                                     -- | refund_reserve | reverse | adjust
  created_at  INTEGER NOT NULL
);

CREATE INDEX idx_entries_txn ON balance_entries(txn_id);

-- The pre-settlement record, and the only place an unpaid invoice exists. A
-- txns row (kind invoice_in) is created only when the invoice settles, inside
-- the same transaction that credits the wallet.
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
);

CREATE TABLE nwc_connections (
  id               INTEGER PRIMARY KEY,
  name             TEXT NOT NULL,
  service_privkey  TEXT NOT NULL,    -- unique per connection (NIP-47 privacy guidance)
  service_pubkey   TEXT NOT NULL UNIQUE,
  client_pubkey    TEXT NOT NULL,
  client_secret    TEXT NOT NULL,    -- so the URI can be re-displayed by the operator
  permissions      TEXT NOT NULL,    -- JSON array of permission GROUPS (§8)
  budget_msat      INTEGER,          -- NULL = unlimited (still bounded by the ceiling)
  budget_period    TEXT,             -- daily | weekly | monthly | never
  budget_used_msat INTEGER NOT NULL DEFAULT 0,
  budget_renews_at INTEGER,
  max_payment_msat INTEGER,
  created_at       INTEGER NOT NULL,
  last_used_at     INTEGER,
  revoked          INTEGER NOT NULL DEFAULT 0
);

-- Durable NWC request idempotency. A replayed request id returns the cached
-- response instead of executing again (§8). Pruned hourly: rows older than 24 h
-- are deleted.
CREATE TABLE nwc_handled_requests (
  event_id      TEXT PRIMARY KEY,      -- the kind 23194 event id
  connection_id INTEGER NOT NULL REFERENCES nwc_connections(id),
  method        TEXT NOT NULL,
  response_json TEXT NOT NULL,         -- plaintext response, re-encrypted on replay
  handled_at    INTEGER NOT NULL
);

CREATE INDEX idx_handled_at ON nwc_handled_requests(handled_at);

-- Security-event history (§12). Money is audited by txns above. The writer and
-- the 10k retention sweep live with the logging work, not here.
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
);

CREATE INDEX idx_audit_created ON audit_events(created_at DESC);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
