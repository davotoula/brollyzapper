-- d24.18: a pairing carries a LIST of relays, not one.
--
-- WHY THE COLUMN CHANGES SHAPE. A connection has been pinned to the single relay
-- named in its pairing URI since migration 0009, so one bad relay minute is a
-- total outage for that pairing — which the 0.1.10 field trip measured rather
-- than supposed: relay.damus.io refused 8 of 20 websocket upgrades from inside
-- the app's container while two other relays took every one. NIP-47's URI
-- permits repeated `relay` parameters, so the pairing can carry several without
-- inventing anything, and both ends then stop depending on one host.
--
-- THIS IS A RENAME THAT CARRIES A VALUE ACROSS, which is a named failure shape
-- in this directory's README: migration 0004 renamed the rate-limit pair, brought
-- the stored values with them, and every upgraded box then ran a global backstop
-- six times tighter than anyone had chosen — because the rename had changed what
-- the number MEANT. The test for that lesson is the one that matters here, and
-- what it asserts is the opposite conclusion: the meaning does NOT change. The
-- same relay, in a list of one, is the same pairing pointed at the same host. A
-- migrated connection is exactly as fragile as it was yesterday and no more, and
-- the Connections page says so rather than implying it gained something.
--
-- A REBUILD rather than ADD COLUMN + UPDATE + DROP COLUMN, and the reason is the
-- test: this migration touches DATA, so it needs a test that seeds the shapes it
-- will meet on a real box — and the way this repository writes that test is to
-- rewind the ledger by one version and run the migration again over real rows.
-- An ALTER-based version cannot be re-run (the column already exists, the old one
-- is already gone), so it could only ever be tested against an empty database,
-- which is the exact hole 0008 fell into. The rebuild is re-runnable, so the test
-- can be real.
--
-- nwc_handled_requests references nwc_connections(id), so the rebuild declares
-- itself and the runner disables foreign keys around it and runs
-- foreign_key_check inside the transaction before committing.
-- +brollyzapper:rebuild-with-foreign-keys-off

-- AND IT ARRIVES WITH A REPAIR (amended 2026-08-26, BrollyZap-dsi). That
-- foreign_key_check is what makes the rebuild safe, and on a database holding
-- rows whose connection no longer exists it also made the app refuse to start —
-- with no operator remedy short of hand-editing sqlite. `repairs[12]` in
-- internal/store/repair_0012.go runs inside this migration's transaction,
-- immediately before this file, and leaves the database consistent: an orphaned
-- payment keeps its row with nwc_connection_id NULL, and an orphaned replay-cache
-- row is dropped. The reasoning for the asymmetry, and for why the orphans are
-- not this app's doing, is written there.
--
-- AMENDED IN PLACE rather than followed by an 0013, and that is only safe
-- because no release contains 0012: on a database that already has version 12
-- the repair had nothing to do, so amending changes nothing for anyone who got
-- here and fixes it for everyone who could not. Migrations are append-only ONCE
-- RELEASED — the same reasoning Wave 28 used to amend 0011.

-- The column definitions are copied VERBATIM from the migrations that created
-- them — 0001 for the original table and 0011 for the refusal columns — comments
-- included. A rebuild is a rename in disguise, and this directory's README says
-- so: a DEFAULT or a comment retyped from memory silently becomes the schema,
-- and the first version of this file lost five of these comments without
-- anything failing.
CREATE TABLE nwc_connections_new (
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
);

-- The carry. An empty relay stays empty rather than becoming a list containing
-- an empty string: a row with no relay could never be served, and `[""]` would
-- turn "this pairing is broken" into "this pairing has one relay, which is
-- nothing" — a distinction the service acts on.
INSERT INTO nwc_connections_new
  (id, name, service_privkey, service_pubkey, client_pubkey, client_secret, relays,
   permissions, budget_msat, budget_period, budget_used_msat, budget_renews_at,
   max_payment_msat, created_at, last_used_at, revoked,
   last_refusal_code, last_refusal_message, last_refusal_at)
SELECT id, name, service_privkey, service_pubkey, client_pubkey, client_secret,
       -- TRIM with an explicit set, because sqlite's one-argument TRIM strips
       -- SPACES only: a tab-or-newline-only relay would otherwise migrate to a
       -- list containing whitespace rather than to an empty one. Both are refused
       -- downstream, so the operator sees the same thing either way — but the
       -- sentence above says "an empty relay stays empty", and it should be true.
       CASE WHEN TRIM(relay, char(32) || char(9) || char(10) || char(13)) = ''
            THEN '[]' ELSE json_array(relay) END,
       permissions, budget_msat, budget_period, budget_used_msat, budget_renews_at,
       max_payment_msat, created_at, last_used_at, revoked,
       last_refusal_code, last_refusal_message, last_refusal_at
  FROM nwc_connections;

DROP TABLE nwc_connections;
ALTER TABLE nwc_connections_new RENAME TO nwc_connections;
