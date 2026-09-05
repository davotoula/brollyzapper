package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/nwc"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/web"
	gonostr "github.com/nbd-wtf/go-nostr"
)

// sentinel is planted in every secret-bearing type; §13 asks for exactly this
// test and §16 asks for it first.
const sentinel = "s3ntinel-must-never-be-logged-9f3a1c"

// subject is one type under the rule, and how to read its secrets back OUT of
// the value being tested.
//
// THE READ-BACK IS THE POINT, and it is a `func() string` rather than a string
// for a reason measured on 2026-09-02 (0vk.33). The check is
// `strings.Contains(record, secret)`, so an entry whose value does not actually
// hold the secret passes however broken its LogValue is — and three of the
// eight entries here were in that state or one edit from it:
//
//   - config.Guard held no secret.String at all, so no sentinel could be in it
//     and Contains had nothing to match. It has moved to its own assertion.
//   - nostr.Identity was built from gonostr.GeneratePrivateKey() while the test
//     looked for the sentinel: the one entry guarding §12's headline secret
//     could not fail.
//   - config.Server was live, but deleting the two env lines that set its
//     secrets was measured to make its entry pass WITH a leak planted in
//     LogValue.
//
// Declaring the secret as a constant beside the value does not fix this — that
// is a second statement, and it can be wrong in the same way twice, which is
// the failure this file already documents for the audit vocabulary further
// down. Reading it back through secret.String.Reveal means an entry that has
// stopped carrying its secret returns "" and says so.
type subject struct {
	value   any
	secrets map[string]func() string // field name -> reads that secret out of value
}

// redactionSubjects builds the table, so that both the rule that renders every
// entry and the rule that checks the table is COMPLETE
// (TestEverySecretBearingTypeIsCoveredByOneOfTheTwoConventions) read the same
// one. Two copies of it would be the second statement this file already
// documents the cost of twice.
func redactionSubjects(t *testing.T) map[string]subject {
	t.Helper()
	// Distinct per field, so a failure names WHICH secret escaped rather than
	// only which type.
	const (
		adminPassword = sentinel + "-admin-password"
		sessionSecret = sentinel + "-session-secret"
	)
	serverCfg, err := config.LoadServer(fixedEnv(map[string]string{
		"LND_ADDRESS":     "10.21.21.9:10009",
		"CREDENTIALS_DIR": "/credentials",
		"DATA_DIR":        "/data",
		"ADMIN_PASSWORD":  adminPassword,
		"SESSION_SECRET":  sessionSecret,
	}))
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}

	// nostr.Identity is the one subject whose secret cannot be read back: there
	// is no accessor for the private half, deliberately (identity.go:38). So the
	// key is generated here and kept — and tied to the value under test by its
	// public half, which is derived from the same key and IS exported. Without
	// that, this entry is a constant sitting next to an unrelated identity,
	// which is what it was.
	privateKey := gonostr.GeneratePrivateKey()
	identity, err := nostr.Parse(secret.New(privateKey))
	if err != nil {
		t.Fatalf("nostr.Parse: %v", err)
	}
	wantPublic, err := gonostr.GetPublicKey(privateKey)
	if err != nil {
		t.Fatalf("gonostr.GetPublicKey: %v", err)
	}
	if identity.PublicKey() != wantPublic {
		t.Fatalf("the identity under test was not built from the key this test looks for; "+
			"its entry below would prove nothing (public %q, want %q)",
			identity.PublicKey(), wantPublic)
	}

	plain := secret.New(sentinel)
	conn := store.NWCConnection{Name: "app", ServicePrivkey: secret.New(sentinel + "-privkey"), ClientSecret: secret.New(sentinel + "-client"), ServicePubkey: strings.Repeat("a", 64), Relays: []string{"wss://relay.example"}}
	zap := store.SettledZap{PaymentHash: strings.Repeat("b", 64), Preimage: secret.New(sentinel + "-preimage")}
	setup := web.SetupView{GeneratedPassword: secret.New(sentinel + "-generated")}
	auth := api.AuthOptions{AppPassword: secret.New(sentinel + "-app"), SessionSecret: secret.New(sentinel + "-session")}
	pay := nwc.PayResult{Settled: true, FeeMsat: 21, Preimage: secret.New(sentinel + "-pay-preimage")}

	// Hand-kept, and it is the arch rule TestEverySecretBearingStructRedactsItself
	// that stops it narrowing silently: that rule fails when a struct gains a
	// secret.String without a LogValue, which is the moment an entry is missing
	// here. Both exist because they catch different halves — the rule proves the
	// method is DECLARED, this proves what it declares does not leak.
	//
	// "Stops it narrowing" is weaker than it reads, so it no longer has to:
	// TestEverySecretBearingTypeIsCoveredByOneOfTheTwoConventions reads the
	// secret-bearing types out of the source and fails when one is neither here
	// nor covered by a rendered-record test beside it (BrollyZap-0vk.36). That
	// rule is what makes this map complete rather than merely long — nwc.PayResult
	// and api.Auth were both absent, and both arch rules passed.
	//
	// AN ENTRY IS NOT THE ONLY ANSWER and must not become the reflex. A type
	// whose secret has no accessor cannot be read back from this package, which
	// is an external test package; that type belongs in an INTERNAL test beside
	// itself, carrying a //redaction:covers marker. api.Auth went that way.
	return map[string]subject{
		"secret.String": {plain, map[string]func() string{"value": plain.Reveal}},
		"config.Server": {serverCfg, map[string]func() string{
			"AdminPassword": serverCfg.AdminPassword.Reveal,
			"SessionSecret": serverCfg.SessionSecret.Reveal,
		}},
		"store.NWCConnection": {conn, map[string]func() string{
			"ServicePrivkey": conn.ServicePrivkey.Reveal,
			"ClientSecret":   conn.ClientSecret.Reveal,
		}},
		"store.SettledZap": {zap, map[string]func() string{"Preimage": zap.Preimage.Reveal}},
		"nostr.Identity":   {identity, map[string]func() string{"private": func() string { return privateKey }}},
		"web.SetupView": {setup, map[string]func() string{
			"GeneratedPassword": setup.GeneratedPassword.Reveal,
		}},
		"api.AuthOptions": {auth, map[string]func() string{
			"AppPassword":   auth.AppPassword.Reveal,
			"SessionSecret": auth.SessionSecret.Reveal,
		}},
		"nwc.PayResult": {pay, map[string]func() string{"Preimage": pay.Preimage.Reveal}},
	}
}

func TestNoSecretBearingTypeEverReachesTheLog(t *testing.T) {
	subjects := redactionSubjects(t)
	levels := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}

	for name, s := range subjects {
		if len(s.secrets) == 0 {
			t.Errorf("%s declares no secret to look for, so its entry cannot fail", name)
			continue
		}
		leaking := map[string]string{}
		for field, reveal := range s.secrets {
			value := reveal()
			if value == "" {
				t.Errorf("%s.%s is empty, so this entry would pass against a value that had "+
					"nothing to leak; give the fixture a secret or remove the entry", name, field)
				continue
			}
			leaking[field] = value
		}
		for _, level := range levels {
			var buf bytes.Buffer
			lv := logging.NewLevelVar(slog.LevelDebug)
			log := logging.New(&buf, lv)
			log.Log(t.Context(), level, "subject", "value", s.value)
			log.Log(t.Context(), level, "subject", slog.Any("value", s.value))
			got := buf.String()
			for field, value := range leaking {
				if strings.Contains(got, value) {
					// Masked: a test that proves a secret escaped by printing it
					// again into CI output has not finished the job.
					t.Errorf("%s leaked %s at %v: %s", name, field, level,
						strings.ReplaceAll(got, value, "<"+field+">"))
				}
			}
		}
	}
}

// config.Guard was one of the subjects above and could never have failed there:
// it holds no secret.String, so nothing could be planted in it and Contains had
// nothing to match. That is not a reason to stop caring — the guard's whole
// config IS logged, at cmd/brollyguard/main.go:60, by the process that holds
// admin.macaroon — so the fact the old entry silently relied on is asserted
// here instead.
//
// The day Guard gains a secret this fails and says what to do: the arch rule
// will already be demanding a LogValue, and this demands the table entry that
// proves the LogValue works.
func TestGuardConfigHoldsNoSecretAndSoNeedsNoRedactionEntry(t *testing.T) {
	guard := reflect.TypeOf(config.Guard{})
	secretString := reflect.TypeOf(secret.String{})
	for i := range guard.NumField() {
		if f := guard.Field(i); f.Type == secretString {
			t.Errorf("config.Guard.%s is a secret.String; Guard is now a secret-bearing type "+
				"and needs an entry in TestNoSecretBearingTypeEverReachesTheLog, which is "+
				"what proves its LogValue actually redacts", f.Name)
		}
	}
}

// §12 requires the level to change without a container restart.
func TestLogLevelChangesWithoutARestart(t *testing.T) {
	var buf bytes.Buffer
	lv := logging.NewLevelVar(slog.LevelInfo)
	log := logging.New(&buf, lv)

	log.Debug("quiet")
	if buf.Len() != 0 {
		t.Fatalf("debug was emitted at info level: %s", buf.String())
	}
	log.Info("loud")
	if !strings.Contains(buf.String(), "loud") {
		t.Fatalf("info was not emitted: %s", buf.String())
	}

	buf.Reset()
	lv.Set(slog.LevelDebug)
	log.Debug("now audible")
	if !strings.Contains(buf.String(), "now audible") {
		t.Errorf("debug was still suppressed after the level was raised: %s", buf.String())
	}

	buf.Reset()
	lv.Set(slog.LevelError)
	log.Warn("suppressed again")
	if buf.Len() != 0 {
		t.Errorf("warn survived a move to error level: %s", buf.String())
	}
}

// §12's audit vocabulary, written out. A typo in the constants fails here
// rather than vanishing into the trail.
func TestAuditVocabularyMatchesTheSpec(t *testing.T) {
	want := []string{
		"auth.ok", "auth.fail",
		"macaroon.bake", "macaroon.revoke", "macaroon.rotate",
		"connection.create", "connection.revoke",
		"nwc.panic", "connection.pause", "connection.resume",
		"sending.toggle", "setting.change", "domain.probe",
		"guard.reject", "guard.register",
		"preflight.repair", "preflight.refuse",
		"wallet.shortfall", "wallet.allocate", "wallet.deallocate", "wallet.adjust", "wallet.assert",
		"zap.receipt.abandoned",
		"relay.refuse",
		"connection.refuse", "connection.update",
		"guard.authorise",
	}
	var got []string
	for _, e := range logging.Events {
		got = append(got, string(e))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Errorf("audit vocabulary = %v, want %v (spec §12)", got, want)
	}
	for _, e := range logging.Events {
		if !e.Valid() {
			t.Errorf("%q is in Events but reports itself invalid", e)
		}
	}
	if logging.Event("macaroon.bakes").Valid() {
		t.Error("a typo'd event reported itself valid")
	}
}

// §12: security is a dimension, not a level — the attribute is what an operator
// filters on, at whatever severity fits.
func TestAuditAttributeIsADimensionNotALevel(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))
	log.Info("spend macaroon baked", logging.Audit(logging.EventMacaroonBake))
	log.Warn("admin login failed", logging.Audit(logging.EventAuthFail))

	var infoLine, warnLine map[string]any
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 log lines, got %d: %s", len(lines), buf.String())
	}
	if err := json.Unmarshal([]byte(lines[0]), &infoLine); err != nil {
		t.Fatalf("line 1 is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &warnLine); err != nil {
		t.Fatalf("line 2 is not JSON: %v", err)
	}
	if infoLine["audit"] != "macaroon.bake" || infoLine["level"] != "INFO" {
		t.Errorf("baking a macaroon logged as %v/%v, want macaroon.bake at INFO", infoLine["audit"], infoLine["level"])
	}
	if warnLine["audit"] != "auth.fail" || warnLine["level"] != "WARN" {
		t.Errorf("a failed login logged as %v/%v, want auth.fail at WARN", warnLine["audit"], warnLine["level"])
	}
}

// §12: truncate identifiers rather than dropping them.
func TestIdentifiersAreTruncatedNotDropped(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var buf bytes.Buffer
	log := logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))
	log.Info("invoice minted", logging.PaymentHash(hash))
	out := buf.String()
	if strings.Contains(out, hash) {
		t.Errorf("the full payment hash was logged: %s", out)
	}
	if !strings.Contains(out, hash[:8]) {
		t.Errorf("the payment hash prefix is missing, so nothing can be correlated: %s", out)
	}
}

// §12: an audit event is written alongside the log line, never instead of it.
func TestAuditorWritesBothTheLineAndTheRow(t *testing.T) {
	var buf bytes.Buffer
	s := openStore(t)
	auditor := logging.NewAuditor(logging.New(&buf, logging.NewLevelVar(slog.LevelDebug)), s)

	err := auditor.Record(t.Context(), slog.LevelWarn, "guard rejected payment",
		logging.EventGuardReject, slog.String("reason", "window_cap"))
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "guard.reject") || !strings.Contains(out, "window_cap") {
		t.Errorf("log line missing the audit attribute or detail: %s", out)
	}
	events, err := s.AuditEvents(t.Context(), 10)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("wrote %d audit rows, want 1", len(events))
	}
	if events[0].Event != logging.EventGuardReject || events[0].Severity != "warn" {
		t.Errorf("row = %+v, want guard.reject at warn", events[0])
	}
	if !strings.Contains(events[0].Detail, "window_cap") {
		t.Errorf("row detail = %q, want it to carry the attributes", events[0].Detail)
	}
}

// d46.18: a relayed event carries the ORIGINATOR's timestamp into the row, and
// writes no second log line — the guard already emitted one when the event
// happened, and a line stamped at delivery time answers "when did this happen?"
// with the wrong number.
func TestRelayStoresTheOriginatorsTimestampAndLogsNothing(t *testing.T) {
	var buf bytes.Buffer
	s := openStore(t)
	auditor := logging.NewAuditor(logging.New(&buf, logging.NewLevelVar(slog.LevelDebug)), s)
	happened := time.Unix(1_700_000_000, 0).UTC()

	stored, err := auditor.Relay(t.Context(), logging.RelayedEvent{
		ID: "guard-abc:1", At: happened, Level: slog.LevelInfo,
		Event: logging.EventMacaroonBake, Attrs: map[string]string{"permissions": "5"},
	})
	if err != nil || !stored {
		t.Fatalf("Relay = (%v, %v), want it stored", stored, err)
	}
	if buf.Len() != 0 {
		t.Errorf("Relay wrote a log line: %s", buf.String())
	}
	events, err := s.AuditEvents(t.Context(), 10)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("wrote %d rows, want 1", len(events))
	}
	if events[0].CreatedAt != happened {
		t.Errorf("row stamped %v, want the originating time %v", events[0].CreatedAt, happened)
	}
	if !strings.Contains(events[0].Detail, "permissions") {
		t.Errorf("row detail = %q, want the relayed attributes", events[0].Detail)
	}
}

// The same two refusals Record has, on the path that arrives over a socket —
// where the caller is another process and the vocabulary is easier to drift.
func TestRelayRefusesAnUnknownEventOrAMissingSourceID(t *testing.T) {
	auditor := logging.NewAuditor(logging.New(io.Discard, logging.NewLevelVar(slog.LevelDebug)),
		openStore(t))
	good := logging.RelayedEvent{ID: "guard-abc:1", Event: logging.EventMacaroonBake}

	outside := good
	outside.Event = logging.Event("macaroon.bakes")
	if _, err := auditor.Relay(t.Context(), outside); err == nil {
		t.Error("Relay accepted an event outside the §12 vocabulary")
	}
	anonymous := good
	anonymous.ID = ""
	if _, err := auditor.Relay(t.Context(), anonymous); err == nil {
		t.Error("Relay accepted an event with no source id; every poll would append a row")
	}
}

func TestAuditorRejectsAnEventOutsideTheVocabulary(t *testing.T) {
	var buf bytes.Buffer
	auditor := logging.NewAuditor(logging.New(&buf, logging.NewLevelVar(slog.LevelDebug)), openStore(t))
	err := auditor.Record(t.Context(), slog.LevelInfo, "typo", logging.Event("macaroon.bakes"))
	if err == nil {
		t.Error("Record accepted an event outside the §12 vocabulary")
	}
}

// §12: one grep should reconstruct a zap end to end. The path traced here is
// the one that exists at P1 — mint, settle — with a req_id from the request
// that minted the invoice and the payment hash on every line.
func TestPaymentHashAndRequestIDCorrelateAcrossTheTracedPath(t *testing.T) {
	const hash = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
	var buf bytes.Buffer
	s := openStore(t)
	base := logging.New(&buf, logging.NewLevelVar(slog.LevelDebug))

	// The inbound request: a req_id is minted and carried on the context.
	ctx, reqID := logging.WithRequestID(context.Background(), base)
	if reqID == "" {
		t.Fatal("WithRequestID returned an empty id")
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	inv := store.Invoice{
		PaymentHash: hash, AmountMsat: 21_000, DescriptionHash: "dh", Bolt11: "lnbcrt1",
		State: store.InvoiceOpen, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := s.CreateInvoice(ctx, inv); err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	logging.FromContext(ctx).Info("invoice minted", logging.PaymentHash(hash))

	// Minutes later, on the invoice stream, with no request context at all.
	if _, err := s.CreditSettledInvoice(context.Background(), hash, "preimage", 21_000, now.Add(time.Minute), true); err != nil {
		t.Fatalf("SettleInvoice: %v", err)
	}
	base.Info("invoice settled", logging.PaymentHash(hash))

	var withHash, withReqID int
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(line, hash[:8]) {
			withHash++
		}
		if strings.Contains(line, reqID) {
			withReqID++
		}
	}
	if withHash != 2 {
		t.Errorf("%d lines carry the payment hash, want 2 — the two halves cannot be joined", withHash)
	}
	if withReqID != 1 {
		t.Errorf("%d lines carry the req_id, want 1 (the request-scoped half)", withReqID)
	}
}

func fixedEnv(m map[string]string) config.Lookup {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Every Event constant must be in Events, because Events is what Valid — and
// therefore Auditor.Record — actually reads.
//
// The list above is a second statement of the vocabulary, and a second
// statement can be incomplete in the same way twice: `xmc` declared
// EventNWCPanic, EventConnectionPause and EventConnectionResume, added them to
// neither, and Record rejected all three before writing the log line OR the
// row. Fix C's whole deliverable recorded nothing, and every test passed —
// the ones that exercise it do so through a fake Auditor, which has no Valid
// gate to fail. So this rule does not restate the vocabulary; it reads the
// declarations out of the source and asserts the slice covers them.
func TestEveryDeclaredEventIsInTheVocabulary(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "audit.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing audit.go: %v", err)
	}
	inVocabulary := make(map[string]bool, len(logging.Events))
	for _, e := range logging.Events {
		inVocabulary[string(e)] = true
	}
	var declared int
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		id, ok := spec.Type.(*ast.Ident)
		if !ok || id.Name != "Event" {
			return true
		}
		for i, name := range spec.Names {
			if i >= len(spec.Values) {
				continue
			}
			lit, ok := spec.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Errorf("%s has an unreadable value %s", name.Name, lit.Value)
				continue
			}
			declared++
			if !inVocabulary[value] {
				t.Errorf("%s (%q) is declared but missing from Events, so Valid rejects it "+
					"and Auditor.Record writes neither the line nor the row", name.Name, value)
			}
		}
		return true
	})
	if declared == 0 {
		t.Fatal("found no Event declarations in audit.go; this rule is reading the wrong thing")
	}
	if declared != len(logging.Events) {
		t.Errorf("audit.go declares %d events but Events has %d; Events has an entry that is "+
			"not a declared constant", declared, len(logging.Events))
	}
}
