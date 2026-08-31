package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/lnurl"
)

// zu5.3 criterion 1, and coverage analysis §3.2.
//
// minSendable and maxSendable are ADVERTISED to every wallet in the LNURL-pay
// document, and internal/lnurl/service.go is the only place that advertisement
// is honoured. Nothing asserted that a callback one millisatoshi below the
// minimum is refused, or — the half that would actually break wallets — that
// the minimum itself is accepted.
//
// Driven through the real callback rather than the Service directly, because
// the accepted cases have to reach the node and mint: a bounds test that only
// covers the refusals would pass against a callback that refused everything.
//
// Both edges, both directions. An off-by-one in either comparison is invisible
// to any test that checks only the middle of the range.
func TestTheAdvertisedAmountBoundsAreTheOnesEnforced(t *testing.T) {
	for _, tc := range []struct {
		name       string
		amountMsat int64
		accepted   bool
	}{
		{"one below the minimum", lnurl.MinSendableMsat - 1, false},
		{"exactly the minimum", lnurl.MinSendableMsat, true},
		{"exactly the maximum", lnurl.MaxSendableMsat, true},
		{"one above the maximum", lnurl.MaxSendableMsat + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newLNURLHarness(t)

			// The document a wallet reads FIRST. Asserting the callback against
			// the numbers the document announces is the whole point — a
			// callback enforcing bounds it does not advertise is the same bug
			// as one advertising bounds it does not enforce.
			var doc lnurl.PayResponse
			if err := json.Unmarshal(h.get(t, "/.well-known/lnurlp/bob", nil).Body.Bytes(), &doc); err != nil {
				t.Fatalf("the address document is not JSON: %v", err)
			}
			if doc.MinSendable != lnurl.MinSendableMsat || doc.MaxSendable != lnurl.MaxSendableMsat {
				t.Fatalf("the document advertises %d..%d but the test is checking %d..%d",
					doc.MinSendable, doc.MaxSendable, lnurl.MinSendableMsat, lnurl.MaxSendableMsat)
			}

			rec := h.get(t, fmt.Sprintf("/lnurlp/bob/callback?amount=%d", tc.amountMsat), nil)
			if rec.Code != http.StatusOK {
				// LNURL has no error status codes; every answer is a 200.
				t.Fatalf("callback = %d %q", rec.Code, rec.Body)
			}
			var answer map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
				t.Fatalf("not JSON: %v (%s)", err, rec.Body)
			}

			if tc.accepted {
				if answer["status"] == "ERROR" {
					t.Fatalf("%d msat was refused: %v", tc.amountMsat, answer["reason"])
				}
				if answer["pr"] == nil || answer["pr"] == "" {
					t.Errorf("accepted %d msat but minted no invoice: %s", tc.amountMsat, rec.Body)
				}
				return
			}
			if answer["status"] != "ERROR" {
				t.Fatalf("%d msat was accepted: %s", tc.amountMsat, rec.Body)
			}
			// The reason has to name the rule: §7 shows this string to a
			// wallet, and "invalid amount" sends its author to the wrong line.
			if reason, _ := answer["reason"].(string); !strings.Contains(reason, "between") {
				t.Errorf("reason = %q, want it to name the bounds", reason)
			}
			if len(h.minted(t)) != 0 {
				t.Error("a refused amount minted an invoice anyway")
			}
		})
	}
}
