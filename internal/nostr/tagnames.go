package nostr

import (
	"log/slog"
	"slices"
	"strings"

	gonostr "github.com/nbd-wtf/go-nostr"
)

// TagNames is the NAMES of an event's tags, sorted, for a log line.
//
// Names only. A tag's value can be anything at all — a paired client's choice on
// an inbound NWC request, a preimage on a zap receipt — and the name is what says
// which shape of event this is: the 0.1.11 investigation needed exactly that of a
// request, and the 0.1.21-rc1 trip needed it of a receipt it could not read back
// from the relays (k2z). Sorted so two events carrying the same tags produce the
// same line and a reader can compare them at a glance.
//
// A LogValuer rather than a function call, and that is not style: slog evaluates
// its arguments EAGERLY, so a function as an argument would allocate, sort and
// join on every inbound request of every install — DEBUG is off on all of them.
// Measured before changing it. LogValue runs only when a handler actually formats
// the record, which is what makes this free when nobody is investigating.
type TagNames struct{ Event *gonostr.Event }

// LogValue is the sorted, comma-joined names.
func (t TagNames) LogValue() slog.Value {
	names := make([]string, 0, len(t.Event.Tags))
	for _, tag := range t.Event.Tags {
		if len(tag) > 0 {
			names = append(names, tag[0])
		}
	}
	slices.Sort(names)
	return slog.StringValue(strings.Join(names, ","))
}
