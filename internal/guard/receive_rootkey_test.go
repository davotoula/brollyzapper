package guard_test

import (
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/davotoula/brollyzapper/internal/guard"
	"github.com/davotoula/brollyzapper/internal/lnd/lndtest"
)

// `0vk.11`: Status answers "does the node still list the receive credential's
// root key" the way it answers for spend — asked, and listed, as two facts.
//
// The three states the Security panel renders differently: listed; asked and
// not listed (revoked, or the node's macaroons rotated); and not asked, which
// must never read as the second.
func TestStatusReportsWhetherTheNodeStillListsTheReceiveRootKey(t *testing.T) {
	node := lndtest.Start(t)
	g, _ := newGuard(t, node)
	if err := g.EnsureReceiveMacaroon(t.Context()); err != nil {
		t.Fatalf("EnsureReceiveMacaroon: %v", err)
	}

	status, err := g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.ReceiveRootKeyChecked || !status.ReceiveRootKeyListed {
		t.Errorf("just after baking: checked=%v listed=%v, want both true",
			status.ReceiveRootKeyChecked, status.ReceiveRootKeyListed)
	}

	node.SetListMacaroonIDsError(errors.New("the node is busy"))
	status, err = g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.ReceiveRootKeyChecked {
		t.Error("Status says the receive root key was checked while the node could not be asked")
	}
	node.SetListMacaroonIDsError(nil)

	node.ForgetRootKeys()
	status, err = g.Status(t.Context())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.ReceiveRootKeyChecked || status.ReceiveRootKeyListed {
		t.Errorf("after the node forgot its keys: checked=%v listed=%v, want checked and not listed",
			status.ReceiveRootKeyChecked, status.ReceiveRootKeyListed)
	}
}

// `0vk.11` criterion 7: the fields are ADDITIVE. A guard that predates them — the
// two containers can be different versions for the length of an update — sends a
// status without them, and the client must decode it rather than refuse it.
//
// A HAND-WRITTEN REPLY, because no guard built from this tree can omit them.
// internal/preflight asserts what the page makes of the zero values that result.
func TestAStatusFromAGuardWithoutTheReceiveRootKeyFieldsDecodes(t *testing.T) {
	socket := socketPath(t)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listening on %s: %v", socket, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	// The Status reply as the guard at 0e8eb2d wrote it for a healthy
	// receive-only install: no receive_root_key_* keys at all.
	const old = `{"status":{"receive_macaroon_present":true,"spend_macaroon_present":false,` +
		`"spend_root_key_listed":false,"spend_root_key_recorded":false,"spend_root_key_checked":false,` +
		`"sending_permitted":false,"sending_allowed_by_deployment":true,"sending_latched":false,` +
		`"authorisation_pending":false,"middleware_registered":true,"lnd_reachable":true}}` + "\n"
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Read the request first: closing on an unread request is a broken
			// pipe on the client's write, which is not the case under test.
			var req guard.Request
			_ = json.NewDecoder(conn).Decode(&req)
			_, _ = conn.Write([]byte(old))
			_ = conn.Close()
		}
	}()

	status, err := guard.NewSocketClient(socket, guard.DiscardEvents).Status(t.Context())
	if err != nil {
		t.Fatalf("the client refused a status from an older guard: %v", err)
	}
	if !status.ReceiveMacaroonPresent || !status.LNDReachable {
		t.Fatalf("the fixture did not decode as written: %+v", status)
	}
	if status.ReceiveRootKeyChecked || status.ReceiveRootKeyListed {
		t.Errorf("absent fields decoded as checked=%v listed=%v, want both false",
			status.ReceiveRootKeyChecked, status.ReceiveRootKeyListed)
	}
}
