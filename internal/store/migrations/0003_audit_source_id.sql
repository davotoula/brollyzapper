-- d46.18: guard-originated security events cross the socket and the SERVER
-- writes the row — the guard has no mount for this database and must not have
-- one (§12, §16).
--
-- The guard cannot learn whether a report was stored, so it keeps re-reporting
-- on every poll. source_id is what turns that into one row instead of one per
-- poll, and it is the SERVER's job because the server is the side that knows
-- what it already holds.
ALTER TABLE audit_events ADD COLUMN source_id TEXT;

-- Partial: only relayed rows carry a source id, so the index holds the handful
-- of guard events rather than an entry per locally raised one, and the NULLs
-- never reach it.
CREATE UNIQUE INDEX idx_audit_source ON audit_events(source_id) WHERE source_id IS NOT NULL;
