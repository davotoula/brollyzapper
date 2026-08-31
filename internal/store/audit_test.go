package store_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/davotoula/brollyzapper/internal/logging"
	"github.com/davotoula/brollyzapper/internal/store"
)

func TestAppendAuditEventRoundTrips(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	at := time.Unix(1_700_000_000, 0).UTC()

	err := s.AppendAuditEvent(ctx, logging.AuditEvent{
		Event:     logging.EventAuthFail,
		Severity:  "warn",
		Detail:    `{"attempt":3}`,
		Remote:    "192.0.2.9",
		CreatedAt: at,
	})
	if err != nil {
		t.Fatalf("AppendAuditEvent: %v", err)
	}
	events, err := s.AuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("AuditEvents returned %d rows, want 1", len(events))
	}
	got := events[0]
	if got.Event != logging.EventAuthFail || got.Severity != "warn" || got.Remote != "192.0.2.9" {
		t.Errorf("row = %+v", got)
	}
	if !got.CreatedAt.Equal(at) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, at)
	}
}

func TestAuditEventsAreNewestFirst(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	base := time.Unix(1_700_000_000, 0).UTC()
	for i, event := range []logging.Event{logging.EventAuthOK, logging.EventMacaroonBake, logging.EventSendingToggle} {
		if err := s.AppendAuditEvent(ctx, logging.AuditEvent{
			Event: event, Severity: "info", CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("AppendAuditEvent: %v", err)
		}
	}
	events, err := s.AuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	if len(events) != 3 || events[0].Event != logging.EventSendingToggle || events[2].Event != logging.EventAuthOK {
		t.Errorf("events = %+v, want newest first", events)
	}
}

// §12: retention is bounded — keep the most recent 10,000 — so the trail cannot
// grow without limit on an SD card.
func TestAuditRetentionKeepsTheMostRecentTenThousand(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	base := time.Unix(1_700_000_000, 0).UTC()

	total := store.MaxAuditEvents + 1
	for i := range total {
		if err := s.AppendAuditEvent(ctx, logging.AuditEvent{
			Event:    logging.EventAuthOK,
			Severity: "info",
			// The detail is what identifies which row survived.
			Detail:    `{"n":` + strconv.Itoa(i) + `}`,
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("AppendAuditEvent %d: %v", i, err)
		}
	}

	count, err := s.AuditEventCount(ctx)
	if err != nil {
		t.Fatalf("AuditEventCount: %v", err)
	}
	if count != store.MaxAuditEvents {
		t.Errorf("audit_events holds %d rows, want %d", count, store.MaxAuditEvents)
	}

	// The oldest row is the one that went, and the newest is still there.
	oldest, err := s.AuditEvents(ctx, store.MaxAuditEvents)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	if got := oldest[0].Detail; got != `{"n":`+strconv.Itoa(total-1)+`}` {
		t.Errorf("newest surviving row = %s, want the last one written", got)
	}
	if got := oldest[len(oldest)-1].Detail; got != `{"n":1}` {
		t.Errorf("oldest surviving row = %s, want {\"n\":1} — row 0 should have been trimmed", got)
	}
}

// d46.18 criterion 3, the "not duplicated" half. The guard re-reports its
// events on every socket answer because it cannot learn whether one was stored,
// so the server is the side that has to make redelivery cheap and idempotent.
func TestARelayedEventIsStoredOnceHoweverOftenItIsReported(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	event := logging.AuditEvent{
		Event:     logging.EventMacaroonBake,
		Severity:  logging.SeverityInfo,
		SourceID:  "guard-abc:1",
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
	}

	for i := range 3 {
		stored, err := s.AppendUniqueAuditEvent(ctx, event)
		if err != nil {
			t.Fatalf("AppendUniqueAuditEvent %d: %v", i, err)
		}
		if want := i == 0; stored != want {
			t.Errorf("report %d stored = %v, want %v", i, stored, want)
		}
	}

	// A second, genuinely different event still gets its own row: the dedup is
	// on the id, not on the kind.
	event.SourceID = "guard-abc:2"
	if stored, err := s.AppendUniqueAuditEvent(ctx, event); err != nil || !stored {
		t.Fatalf("a second event stored = %v, err = %v; want it stored", stored, err)
	}

	events, err := s.AuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("the trail holds %d rows after 3 reports of one event and 1 of another, want 2",
			len(events))
	}
	if events[0].CreatedAt != event.CreatedAt {
		t.Errorf("the stored row is stamped %v, want the originating time %v — a delivery "+
			"timestamp would misdate the event", events[0].CreatedAt, event.CreatedAt)
	}
}

// Without a source id there is nothing to dedup on, so a relayed event would
// append a row per poll. That must be a refusal, not a silent daily pile-up.
func TestARelayedEventWithoutASourceIDIsRefused(t *testing.T) {
	s, _ := open(t)
	stored, err := s.AppendUniqueAuditEvent(t.Context(), logging.AuditEvent{
		Event: logging.EventMacaroonBake, Severity: logging.SeverityInfo,
	})
	if err == nil {
		t.Fatalf("AppendUniqueAuditEvent with no source id = (%v, nil), want an error", stored)
	}
}

// Locally raised events carry no source id and must not collide with each
// other: the unique index is partial precisely so NULLs never reach it.
func TestLocalEventsAreUnaffectedByTheRelayIndex(t *testing.T) {
	s, _ := open(t)
	ctx := t.Context()
	for i := range 3 {
		if err := s.AppendAuditEvent(ctx, logging.AuditEvent{
			Event: logging.EventAuthFail, Severity: logging.SeverityWarn,
			CreatedAt: time.Unix(int64(1_700_000_000+i), 0).UTC(),
		}); err != nil {
			t.Fatalf("AppendAuditEvent %d: %v", i, err)
		}
	}
	events, err := s.AuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("AuditEvents: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("the trail holds %d locally raised rows, want 3", len(events))
	}
}
