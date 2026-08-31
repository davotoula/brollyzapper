-- The minute sweep (§4) runs
--   UPDATE invoices SET state='expired' WHERE state='open' AND expires_at <= ?
-- every sixty seconds for the life of the node, and `invoices` keeps every
-- invoice ever minted. Without an index that is a full scan whose cost grows
-- with history rather than with work to do.
--
-- The predicate is load-bearing. A partial index over the open rows only stays
-- near zero entries — an invoice leaves it as soon as it settles or expires —
-- so it costs almost nothing on the write path. A full index over the whole
-- table would trade one problem for another.
CREATE INDEX idx_invoices_open_expiry ON invoices(state, expires_at)
WHERE state = 'open';
