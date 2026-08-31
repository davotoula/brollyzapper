# Writing a migration

Files are `NNNN_name.sql`, applied in order, recorded in `schema_migrations`.
They are **append-only once released**: a migration that has run on any box is
history, and editing it makes two boxes disagree about what their schema means.
A migration still uncommitted in the wave that wrote it may be edited freely.

## A rename must not carry a value whose meaning changed with the rename

**Carry only what differs from the old default.**

This is the rule migration 0007 exists to restate, and it was learned the
expensive way. Migration 0004 renamed `rate_limit_per_min` / `_per_hour` to
`public_rate_limit_per_min` / `_per_hour` and brought the stored values with
them — correct for a number an operator typed, and wrong for a number nobody
chose. The reference box held exactly the latter: the old pair's defaults,
`10/100`. The renamed setting's own default is `60/600`, so every upgraded box
ran a global anonymous backstop six times tighter than designed, and nobody
had picked it. Measured on 0.1.4: the first `429` came at request 11, where the
design expects about 60.

The rename had also changed what the number *meant* — the old pair governed
per-IP buckets and counted the address document; the new one is the global
backstop on the callback alone. So the carried value was not merely stale, it
was a limit on a different thing.

This is the "two statements of one fact" shape with a twist: the two statements
were separated in **time**, not across two files, and the rename is what made
them disagree. A migration cannot see the code's defaults, so it has to be
written knowing them.

When you rename a settings key:

- If the stored value equals the OLD default, delete it. The new default then
  applies, which is what an operator who never chose should get.
- If it differs, carry it. That is a decision somebody made.
- Match on the **whole** set of keys that made up the old default, not one of
  them. An operator who set one half and left the other is a caller who chose.
- Accept that an operator who explicitly chose exactly the old default is
  indistinguishable from one who never chose, and loses that choice. The
  alternative — every upgraded box pinned to a number nobody picked — is worse,
  and invisible.

Test both directions: seed the old default and assert it is gone, and seed a
different value and assert it survives. The second is the one that proves the
migration is not just a `DELETE`.

## A migration that only ran against an empty database has been written, not tested

**Rule: any migration that touches DATA — not just schema — needs a test that
seeds the shapes it will meet on a real box, and re-runs the migration over
them.**

Migration 0008 rebuilds `txns`, which `balance_entries` references. It passed
every store test and then failed on the regtest stack's first start:

```
migration 0008_...: constraint failed: FOREIGN KEY constraint failed (787)
```

Every one of those tests opens a **fresh** database, where the rebuild copies an
empty table and no foreign key has anything to resolve. The rule above is what
`migrate_txns_rebuild_internal_test.go` exists to satisfy, and it is the same
shape as 0004's lesson one section up: the failure lives in the data, and a test
with no data cannot see it.

### Rebuilding a table other tables reference

SQLite cannot drop a column constraint in place, so changing one means the
documented table rebuild — and that procedure requires `PRAGMA foreign_keys =
OFF`, which is a **no-op inside a transaction**, where the runner puts every
migration. Two shortcuts were tried and neither works:

- **`defer_foreign_keys`.** Dropping a parent runs as an implicit `DELETE` of
  every row and records a deferred violation per child row. Recreating the
  parent does not retract them; they are counted again at `COMMIT`.
- **`legacy_alter_table` plus a rename dance**, to avoid dropping a referenced
  table at all. The pragma is not honoured partway through a multi-statement
  migration, so the rename repointed `balance_entries` at the table being thrown
  away — the reference followed the corpse.

So a rebuild declares itself:

```sql
-- +brollyzapper:rebuild-with-foreign-keys-off
```

The runner then takes a **dedicated connection**, sets the pragma *before* the
transaction, and — this is the part that makes it safe — runs `PRAGMA
foreign_key_check` **inside** the transaction before committing. A rebuild that
orphaned a row rolls back rather than shipping. There is a planted test for that
check, because a safety net that has only ever passed has been written rather
than tested.

Copy the column definitions **verbatim** from the migrations that created them.
A rebuild is a rename in disguise, and this file's rule about carrying stale
values applies to `DEFAULT`s too: one retyped from memory silently becomes the
schema.

## A migration must survive a database it did not create

**Rule: a migration meets whatever is on the operator's disk. If it can only run
against a database this app produced, it will one day refuse to run at all — and
a migration that aborts is a server that does not start.**

Migration 0012 rebuilds `nwc_connections`, so the runner's `foreign_key_check`
runs inside its transaction. On the reference box's own volume that check found
125 dangling references — 0 connections, 14 `txns` rows and 111
`nwc_handled_requests` rows pointing at connections that were gone — and the
server crash-looped, with no operator remedy short of hand-editing sqlite.

**The orphans were not this app's doing, and that is the point rather than an
excuse.** `foreign_keys(1)` is in the DSN and has been since Wave 1, so a delete
that orphaned children would have *failed*; there is no `DELETE FROM
nwc_connections` anywhere in the tree, and revocation is an `UPDATE`; no
migration before 0012 rebuilds that table. What is left is an external writer —
the `sqlite3` CLI defaults to `foreign_keys=OFF`. Every orphan a migration meets
therefore arrived by restore, backup, partial recovery, or a human with a shell,
which are exactly the circumstances in which a migration most needs to work.

So: **a migration that needs the database to be consistent has to make it so.**
0012 declares a repair — `repairs[12]` in `internal/store/repair_0012.go` — which
runs inside its transaction, immediately before its SQL. Three things make that
tolerable rather than alarming:

- **It is declared and specific**, keyed to one version. There is no
  general-purpose "repair the database" pass, because a step that silently
  rewrites data on every upgrade is worse than the problem.
- **It says what it changed**, per row kind, at INFO — and says nothing when
  there was nothing to do. "It fixed itself" is not something an operator should
  have to infer from the app starting.
- **It never deletes money.** An orphaned `txns` row is a payment that really
  happened; its link is set to NULL, which is a value the schema, the code and
  the Transactions page already understand. Only the replay cache — a table with
  its own retention sweep, whose rows can no longer be dispatched to anything —
  is deleted from.

**Do not weaken `requireNoDanglingReferences` instead.** The runner-level check
is what makes every rebuild safe; it is the migration that must arrive with the
database already consistent. Relaxing the check would hide the next one.
