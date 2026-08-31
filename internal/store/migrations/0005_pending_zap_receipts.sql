-- o34.3 criterion 9. §7: "A zap that credits the wallet but never publishes a
-- receipt is invisible to the sender and reads as theft."
--
-- So a receipt that no relay accepted is not dropped: it is queued here and
-- retried with backoff for up to 24 hours. The queue is a TABLE rather than an
-- in-memory list because the failure this exists for — every relay unreachable
-- — is exactly the failure that coincides with the box being restarted, and a
-- queue that a restart empties would be a queue that vanishes when it is
-- needed.
--
-- Only the payment hash is stored, not the built receipt. Everything else is
-- rebuilt from the invoice row on each attempt, which is what keeps §7's
-- "read the signing key per use" true for retries as well as for the first
-- send: an operator who replaces the key mid-retry gets receipts signed by the
-- identity their address currently announces, not by the one it had yesterday.
-- created_at is unaffected — it comes from the invoice's settle time, not from
-- the attempt.
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

-- The retry loop asks one question — "what is due now?" — and this is the index
-- that answers it without scanning a table that grows with every failed relay
-- run.
CREATE INDEX idx_pending_receipts_due ON pending_zap_receipts(next_attempt_at);
