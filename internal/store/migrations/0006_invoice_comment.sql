-- o34.12. The callback announces commentAllowed: 255, length-checks what
-- arrives, and then dropped it: a wallet showed "comment accepted" and the
-- comment was gone.
--
-- The ruling was to store it rather than to advertise commentAllowed: 0.
-- Announcing a capability and discarding what it accepts is the option that was
-- ruled out; keeping the advertisement honest costs one column.
--
-- Nullable, because most payments have no comment and an empty string and "the
-- sender wrote nothing" are different facts. It is NOT part of the metadata
-- string and must never be folded into it — LUD-12's comment is not LUD-06's
-- metadata, and the description hash is computed over the metadata.
ALTER TABLE invoices ADD COLUMN comment TEXT;

-- Carried to the settled txn so the transaction history can show it beside the
-- zap. txns.description already exists for the operator-facing line; this is
-- the sender's own words and is kept apart from it.
ALTER TABLE txns ADD COLUMN comment TEXT;
