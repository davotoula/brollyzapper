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
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/api"
	"github.com/davotoula/brollyzapper/internal/config"
	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/nostr"
	"github.com/davotoula/brollyzapper/internal/secret"
	"github.com/davotoula/brollyzapper/internal/store"
	"github.com/davotoula/brollyzapper/internal/web"
	gonostr "github.com/nbd-wtf/go-nostr"
)

// sentinel is planted in every secret-bearing type; §13 asks for exactly this
// test and §16 asks for it first.
const sentinel = "s3ntinel-must-never-be-logged-9f3a1c"

func TestNoSecretBearingTypeEverReachesTheLog(t *testing.T) {
	serverCfg, err := config.LoadServer(fixedEnv(map[string]string{
		"LND_ADDRESS":     "10.21.21.9:10009",
		"CREDENTIALS_DIR": "/credentials",
		"DATA_DIR":        "/data",
		"ADMIN_PASSWORD":  sentinel,
		"SESSION_SECRET":  sentinel,
	}))
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	guardCfg, err := config.LoadGuard(fixedEnv(map[string]string{
		"LND_ADDRESS":        "10.21.21.9:10009",
		"LND_CERT_FILE":      "/lnd/tls.cert",
		"LND_ADMIN_MACAROON": "/lnd/admin.macaroon",
		"DATA_DIR":           "/guard",
		"CREDENTIALS_DIR":    "/credentials",
		"SERVER_IP":          "10.21.0.17",
	}))
	if err != nil {
		t.Fatalf("LoadGuard: %v", err)
	}

	// Hand-kept, and it is the arch rule TestEverySecretBearingStructRedactsItself
	// that stops it narrowing silently: that rule fails when a struct gains a
	// secret.String without a LogValue, which is the moment an entry is missing
	// here. Both exist because they catch different halves — the rule proves the
	// method is DECLARED, this proves what it declares does not leak.
	identity, err := nostr.Parse(secret.New(gonostr.GeneratePrivateKey()))
	if err != nil {
		t.Fatalf("nostr.Parse: %v", err)
	}

	subjects := map[string]any{
		"secret.String":       secret.New(sentinel),
		"config.Server":       serverCfg,
		"config.Guard":        guardCfg,
		"store.NWCConnection": store.NWCConnection{Name: "app", ServicePrivkey: secret.New(sentinel), ClientSecret: secret.New(sentinel), ServicePubkey: strings.Repeat("a", 64), Relays: []string{"wss://relay.example"}},
		"store.SettledZap":    store.SettledZap{PaymentHash: strings.Repeat("b", 64), Preimage: secret.New(sentinel)},
		"nostr.Identity":      identity,
		"web.SetupView":       web.SetupView{GeneratedPassword: secret.New(sentinel)},
		"api.AuthOptions":     api.AuthOptions{AppPassword: secret.New(sentinel), SessionSecret: secret.New(sentinel)},
	}
	levels := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}

	for name, subject := range subjects {
		for _, level := range levels {
			var buf bytes.Buffer
			lv := logging.NewLevelVar(slog.LevelDebug)
			log := logging.New(&buf, lv)
			log.Log(t.Context(), level, "subject", "value", subject)
			log.Log(t.Context(), level, "subject", slog.Any("value", subject))
			if got := buf.String(); strings.Contains(got, sentinel) {
				t.Errorf("%s leaked at %v: %s", name, level, got)
			}
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
