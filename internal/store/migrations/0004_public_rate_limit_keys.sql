-- The rate-limit pair became explicitly the PUBLIC pair (PM ruling, 22 Aug
-- 2026; spec §7).
--
-- One pair used to feed both limiters, so raising the public ceiling until zaps
-- stopped bouncing silently raised the admin login brute-force ceiling by the
-- same amount, from a single unlabelled field (d46.27, review M2). The admin
-- limits are now constants in the code — an operator has no legitimate reason
-- to raise their own brute-force ceiling — and these two rows govern the public
-- callback alone.
--
-- The values move with the keys rather than being dropped: an operator who had
-- raised the limit for zaps meant it for the public side, which is the side
-- that keeps them.
--
-- OR REPLACE, not a bare UPDATE: if a database somehow holds both spellings the
-- rename must not fail on the primary key, and the operator's public value is
-- the one worth keeping.
UPDATE OR REPLACE settings SET key = 'public_rate_limit_per_min'
  WHERE key = 'rate_limit_per_min';
UPDATE OR REPLACE settings SET key = 'public_rate_limit_per_hour'
  WHERE key = 'rate_limit_per_hour';
