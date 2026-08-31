-- o34.14, from the 0.1.4 box. Undo what migration 0004 carried too far.
--
-- 0004 renamed rate_limit_per_min/_per_hour to public_rate_limit_per_min/_per_hour
-- and brought the stored values with them. That is right for a number an
-- operator typed. It is wrong for a number nobody chose — and the reference box
-- held exactly that: the OLD pair's defaults, 10/100.
--
-- The renamed setting's own default is 60/600 (DefaultGlobalBackstopPerMinute,
-- internal/api/publiclimit.go), so every upgraded box ran a global anonymous
-- backstop six times tighter than designed. Measured on 0.1.4: the first 429
-- came at request 11, where the design expects about 60. It fails safe, which
-- is why it was not urgent; it is invisible, which is why it had to be fixed —
-- the next throughput measurement on any upgraded box measures the wrong
-- number and nobody knows it.
--
-- The old value was also a limit on a DIFFERENT thing. Before Wave 10 the pair
-- governed per-IP buckets and counted the address document; now it is the
-- global backstop on the callback alone. Carrying a number across a rename that
-- changed its meaning is what put the box here.
--
-- ACCEPTED COST: an operator who deliberately chose exactly 10/100 is
-- indistinguishable from one who never chose, and loses that choice. The
-- alternative is leaving every upgraded box at a number nobody picked, which is
-- the thing this migration exists to stop. Any other stored pair is left alone.
--
-- Both halves must match. One half matching is not evidence of a default: an
-- operator who set 10/250 chose 10, and this must not touch it.
DELETE FROM settings
 WHERE key IN ('public_rate_limit_per_min', 'public_rate_limit_per_hour')
   AND EXISTS (
     SELECT 1 FROM settings AS m WHERE m.key = 'public_rate_limit_per_min'  AND m.value = '10'
   )
   AND EXISTS (
     SELECT 1 FROM settings AS h WHERE h.key = 'public_rate_limit_per_hour' AND h.value = '100'
   );
