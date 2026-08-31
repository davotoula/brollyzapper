package store_test

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/store"
)

var update = flag.Bool("update", false, "rewrite testdata/schema.golden.sql from the live schema")

func open(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

// Spec §4: the database holds the only copy of the zap-receipt signing key, so
// the directory it sits in is a security control.
func TestOpenCreatesTheDataDirectoryPrivate(t *testing.T) {
	s, dir := open(t)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat data dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("data dir mode = %o, want 700", got)
	}
	dbInfo, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if got := dbInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("database file mode = %o, want 600", got)
	}
}

func TestOpenCreatesEverySpecTable(t *testing.T) {
	s, _ := open(t)
	want := []string{
		"audit_events", "balance_entries", "invoices",
		"nwc_connections", "nwc_handled_requests", "settings", "txns",
	}
	cols, err := s.Columns(t.Context())
	if err != nil {
		t.Fatalf("Columns: %v", err)
	}
	missing := map[string]bool{}
	for _, w := range want {
		missing[w] = true
	}
	for _, c := range cols {
		delete(missing, c.Table)
	}
	for w := range missing {
		t.Errorf("spec §4 table %q was not created", w)
	}
}

// The snapshot is the drift alarm: any schema change has to arrive as a
// reviewed diff to testdata/schema.golden.sql.
func TestSchemaMatchesTheGoldenSnapshot(t *testing.T) {
	s, _ := open(t)
	got, err := s.SchemaDump(t.Context())
	if err != nil {
		t.Fatalf("SchemaDump: %v", err)
	}
	golden := filepath.Join("testdata", "schema.golden.sql")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatalf("writing golden: %v", err)
		}
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden (run: go test ./internal/store -update): %v", err)
	}
	if got != string(want) {
		t.Errorf("schema drifted from %s.\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
	}
}

// Spec §4: all amounts are msat, stored as INTEGER. Never floats for money.
func TestNoColumnUsesAFloatingPointType(t *testing.T) {
	s, _ := open(t)
	allowed := map[string]bool{"INTEGER": true, "TEXT": true, "BLOB": true}
	cols, err := s.Columns(t.Context())
	if err != nil {
		t.Fatalf("Columns: %v", err)
	}
	if len(cols) == 0 {
		t.Fatal("no columns found; the check is not actually running")
	}
	for _, c := range cols {
		if !allowed[strings.ToUpper(c.Type)] {
			t.Errorf("%s.%s is declared %s; money is msat INTEGER and nothing here may be "+
				"REAL, FLOAT or NUMERIC (spec §4)", c.Table, c.Name, c.Type)
		}
	}
}

// Spec §4 and §21: macaroons live in the credential volume, the spend root key
// id lives in the guard's own store. Neither is a column here.
func TestNoTableHasAMacaroonOrRootKeyColumn(t *testing.T) {
	s, _ := open(t)
	cols, err := s.Columns(t.Context())
	if err != nil {
		t.Fatalf("Columns: %v", err)
	}
	for _, c := range cols {
		name := strings.ToLower(c.Name)
		if strings.Contains(name, "macaroon") || strings.Contains(name, "root_key") {
			t.Errorf("%s.%s exists; macaroons and the spend root key id must never be "+
				"in the server's database (spec §4, §6)", c.Table, c.Name)
		}
	}
}

func TestReopeningAnExistingDatabaseIsANoOp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	first, err := store.Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	firstSchema, err := first.SchemaDump(t.Context())
	if err != nil {
		t.Fatalf("SchemaDump: %v", err)
	}
	firstVersion, err := first.SchemaVersion(t.Context())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := store.Open(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer second.Close()
	secondSchema, err := second.SchemaDump(t.Context())
	if err != nil {
		t.Fatalf("SchemaDump: %v", err)
	}
	secondVersion, err := second.SchemaVersion(t.Context())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if firstSchema != secondSchema {
		t.Error("re-opening an already-migrated database changed the schema")
	}
	if firstVersion != secondVersion {
		t.Errorf("schema version moved on restart: %d -> %d", firstVersion, secondVersion)
	}
}

func openInvoice(hash string, amountMsat int64, expires time.Time) store.Invoice {
	return store.Invoice{
		PaymentHash:     hash,
		AmountMsat:      amountMsat,
		DescriptionHash: "dh-" + hash,
		Bolt11:          "lnbcrt-" + hash,
		State:           store.InvoiceOpen,
		CreatedAt:       expires.Add(-time.Hour),
		ExpiresAt:       expires,
	}
}

// Spec §4: `invoices` is the pre-settlement record; a txns(invoice_in) row is
// created only when the invoice settles, in the transaction that credits.
func TestSettlementCreatesTheTxnAndCreditsTheBalance(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	now := time.Unix(1_700_000_000, 0).UTC()
	inv := openInvoice("hash-a", 21_000, now.Add(time.Hour))
	if err := s.CreateInvoice(ctx, inv); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}

	if got, err := s.BalanceMsat(ctx); err != nil || got != 0 {
		t.Fatalf("BalanceMsat before settlement = %d, %v; want 0, nil", got, err)
	}
	if n, err := s.TxnCount(ctx); err != nil || n != 0 {
		t.Fatalf("an unsettled invoice created %d txns; want 0 (%v)", n, err)
	}

	credited, err := s.CreditSettledInvoice(ctx, "hash-a", "preimage-a", 21_000, now, true)
	if err != nil {
		t.Fatalf("CreditSettledInvoice: %v", err)
	}
	if !credited {
		t.Fatal("CreditSettledInvoice reported no credit for a first settlement")
	}
	if got, err := s.BalanceMsat(ctx); err != nil || got != 21_000 {
		t.Fatalf("BalanceMsat after settlement = %d, %v; want 21000, nil", got, err)
	}
	if n, err := s.TxnCount(ctx); err != nil || n != 1 {
		t.Fatalf("TxnCount after settlement = %d; want 1 (%v)", n, err)
	}
	got, ok, err := s.Invoice(ctx, "hash-a")
	if err != nil || !ok {
		t.Fatalf("Invoice: %v, ok=%v", err, ok)
	}
	if got.State != store.InvoiceSettled {
		t.Errorf("invoice state = %q, want %q", got.State, store.InvoiceSettled)
	}
}

// The failure this guards against pays the wallet twice for one zap: LND
// redelivers a settlement after a restart and UNIQUE(payment_hash) must make it
// a no-op.
func TestReplayedSettlementDoesNotCreditTwice(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := s.CreateInvoice(ctx, openInvoice("hash-b", 50_000, now.Add(time.Hour))); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	if _, err := s.CreditSettledInvoice(ctx, "hash-b", "preimage-b", 50_000, now, true); err != nil {
		t.Fatalf("first CreditSettledInvoice: %v", err)
	}
	credited, err := s.CreditSettledInvoice(ctx, "hash-b", "preimage-b", 50_000, now.Add(time.Minute), true)
	if err != nil {
		t.Fatalf("replayed CreditSettledInvoice: %v", err)
	}
	if credited {
		t.Error("a replayed settlement reported a second credit")
	}
	if got, err := s.BalanceMsat(ctx); err != nil || got != 50_000 {
		t.Errorf("BalanceMsat after replay = %d, %v; want 50000, nil", got, err)
	}
	if n, err := s.TxnCount(ctx); err != nil || n != 1 {
		t.Errorf("TxnCount after replay = %d; want 1 (%v)", n, err)
	}
}

func TestSettlingAnUnknownInvoiceIsAnError(t *testing.T) {
	s, _ := open(t)
	_, err := s.CreditSettledInvoice(t.Context(), "never-seen", "p", 1, time.Unix(1, 0), true)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("CreditSettledInvoice for an unknown hash = %v, want ErrNotFound", err)
	}
}

func TestExpireInvoicesMovesOnlyPastDueOpenRows(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	now := time.Unix(1_700_000_000, 0).UTC()

	if err := s.CreateInvoice(ctx, openInvoice("due", 1_000, now.Add(-time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInvoice(ctx, openInvoice("fresh", 1_000, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateInvoice(ctx, openInvoice("paid", 1_000, now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreditSettledInvoice(ctx, "paid", "p", 1_000, now.Add(-2*time.Hour), true); err != nil {
		t.Fatal(err)
	}

	n, err := s.ExpireInvoices(ctx, now)
	if err != nil {
		t.Fatalf("ExpireInvoices: %v", err)
	}
	if n != 1 {
		t.Errorf("ExpireInvoices expired %d rows, want 1", n)
	}
	for hash, want := range map[string]string{
		"due":   store.InvoiceExpired,
		"fresh": store.InvoiceOpen,
		"paid":  store.InvoiceSettled,
	} {
		got, ok, err := s.Invoice(ctx, hash)
		if err != nil || !ok {
			t.Fatalf("Invoice(%s): %v ok=%v", hash, err, ok)
		}
		if got.State != want {
			t.Errorf("invoice %q state = %q, want %q", hash, got.State, want)
		}
	}
	// A second pass has nothing left to do.
	if n, err := s.ExpireInvoices(ctx, now); err != nil || n != 0 {
		t.Errorf("second ExpireInvoices = %d, %v; want 0, nil", n, err)
	}
}

// The minute sweep, driven by an injected tick and an injected clock, so the
// test costs microseconds rather than a minute.
func TestExpirySweepRunsOnEveryTick(t *testing.T) {
	s, _ := open(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	base := time.Unix(1_700_000_000, 0).UTC()
	if err := s.CreateInvoice(ctx, openInvoice("later", 1_000, base.Add(90*time.Second))); err != nil {
		t.Fatal(err)
	}

	now := base
	tick := make(chan time.Time)
	swept := make(chan int64, 4)
	done := make(chan error, 1)
	go func() {
		done <- s.RunExpirySweep(ctx, tick, func() time.Time { return now },
			func(expired int64, err error) {
				if err != nil {
					t.Errorf("sweep reported an error: %v", err)
				}
				swept <- expired
			})
	}()

	tick <- now
	if n := <-swept; n != 0 {
		t.Errorf("first sweep expired %d rows, want 0 — the invoice is not due yet", n)
	}
	now = base.Add(2 * time.Minute)
	tick <- now
	if n := <-swept; n != 1 {
		t.Errorf("second sweep expired %d rows, want 1", n)
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("RunExpirySweep returned %v, want nil or context.Canceled", err)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	if _, ok, err := s.Setting(ctx, "domain"); err != nil || ok {
		t.Fatalf("Setting(domain) on a fresh db = ok %v, %v; want false, nil", ok, err)
	}
	if err := s.SetSetting(ctx, "domain", "zap.example"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := s.SetSetting(ctx, "domain", "zap2.example"); err != nil {
		t.Fatalf("SetSetting overwrite: %v", err)
	}
	got, ok, err := s.Setting(ctx, "domain")
	if err != nil || !ok || got != "zap2.example" {
		t.Errorf("Setting(domain) = %q, %v, %v; want zap2.example, true, nil", got, ok, err)
	}
}

// §4 lists schema_version among the settings keys, so the UI can read it
// without knowing about the migration bookkeeping.
func TestSchemaVersionIsMirroredIntoSettings(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	version, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version < 1 {
		t.Fatalf("SchemaVersion = %d, want at least 1", version)
	}
	got, ok, err := s.Setting(ctx, "schema_version")
	if err != nil || !ok {
		t.Fatalf("Setting(schema_version) = ok %v, %v", ok, err)
	}
	if got != strconv.Itoa(version) {
		t.Errorf("settings.schema_version = %q, want %q", got, strconv.Itoa(version))
	}
}

// The resume point for the invoice stream (spec §6). It lives in settings so
// the admin UI can show it; internal/lnd reaches it through its own consumer
// interface.
func TestSettleIndexRoundTripsAndStartsAtZero(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()

	got, err := s.LastSettleIndex(ctx)
	if err != nil {
		t.Fatalf("LastSettleIndex on a fresh db: %v", err)
	}
	if got != 0 {
		t.Errorf("LastSettleIndex = %d on a fresh db, want 0", got)
	}

	if err := s.SetLastSettleIndex(ctx, 42); err != nil {
		t.Fatalf("SetLastSettleIndex: %v", err)
	}
	if got, err := s.LastSettleIndex(ctx); err != nil || got != 42 {
		t.Errorf("LastSettleIndex = %d, %v; want 42, nil", got, err)
	}
	if err := s.SetLastSettleIndex(ctx, 43); err != nil {
		t.Fatalf("SetLastSettleIndex overwrite: %v", err)
	}
	if got, err := s.LastSettleIndex(ctx); err != nil || got != 43 {
		t.Errorf("LastSettleIndex = %d, %v; want 43, nil", got, err)
	}
}

func TestLastSettleIndexRejectsACorruptedValue(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	if err := s.SetSetting(ctx, "last_settle_index", "not-a-number"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	// Silently resuming from 0 would replay every settlement the node still
	// remembers, so a corrupted value must be an error the caller sees.
	if _, err := s.LastSettleIndex(ctx); err == nil {
		t.Error("LastSettleIndex accepted a non-numeric stored value")
	}
}

// The partial predicate is what keeps the index near zero rows, so it costs
// almost nothing on the write path. A full index would trade one problem for
// another.
func TestTheExpiryIndexIsPartial(t *testing.T) {
	s, _ := open(t)
	dump, err := s.SchemaDump(t.Context())
	if err != nil {
		t.Fatalf("SchemaDump: %v", err)
	}
	if !strings.Contains(dump, "idx_invoices_open_expiry") {
		t.Fatal("the schema has no idx_invoices_open_expiry")
	}
	if !strings.Contains(dump, "WHERE state = 'open'") {
		t.Errorf("the expiry index is not partial:\n%s", dump)
	}
}

// §7's open-invoice cap counts what an attacker actually consumes by calling
// the public callback: a row in LND's invoice database. The count has to match
// that resource, which means excluding rows that no longer hold one.
//
// The past-due case is the one worth stating: the expiry sweep runs once a
// minute, so between ticks the table holds open rows whose invoices LND has
// already forgotten. Counting those would make the cap up to a minute stickier
// than the 600-second expiry it is supposed to self-clear on.
func TestCountingOpenInvoicesExcludesSettledExpiredAndPastDue(t *testing.T) {
	s, _ := open(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	live := openInvoice("live-1", 1_000, now.Add(10*time.Minute))
	alsoLive := openInvoice("live-2", 1_000, now.Add(time.Minute))
	pastDue := openInvoice("past-due", 1_000, now.Add(-time.Second))
	settled := openInvoice("settled", 1_000, now.Add(10*time.Minute))
	for _, inv := range []store.Invoice{live, alsoLive, pastDue, settled} {
		if err := s.CreateInvoice(t.Context(), inv); err != nil {
			t.Fatalf("CreateInvoice(%s): %v", inv.PaymentHash, err)
		}
	}
	if _, err := s.CreditSettledInvoice(t.Context(), settled.PaymentHash, "preimage",
		settled.AmountMsat, now, false); err != nil {
		t.Fatalf("CreditSettledInvoice: %v", err)
	}

	got, err := s.CountOpenInvoices(t.Context(), now)
	if err != nil {
		t.Fatalf("CountOpenInvoices: %v", err)
	}
	if got != 2 {
		t.Errorf("CountOpenInvoices = %d, want 2 (the settled, and the past-due "+
			"one the sweep has not reached yet, hold no invoice on the node)", got)
	}
}
