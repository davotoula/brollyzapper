package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"
)

// socketTimeout bounds one request. The peer is the server container on the
// same host through a shared volume, so anything slower is a stuck connection.
const socketTimeout = 30 * time.Second

// Serve accepts requests on a unix domain socket until ctx ends.
//
// A unix socket in the shared volume, never a TCP port (§3, §6): the guard has
// no listener anything off the box could ever reach, and an arch test asserts
// this package cannot grow one.
//
// It returns ErrMacaroonRotated when the node has stopped accepting
// admin.macaroon, after the settling delay — the caller's job is then to exit
// non-zero so restart: on-failure re-performs the bind mount and picks up the
// replaced inode. That bounded exit is the one sanctioned exit in the codebase.
func (g *Guard) Serve(ctx context.Context, socketPath string) error {
	// A socket left behind by a killed container would make Listen fail; the
	// path is inside our own credential volume, so removing it is safe.
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("guard: clearing %s: %w", socketPath, err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("guard: listening on %s: %w", socketPath, err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("guard: securing %s: %w", socketPath, err)
	}

	accepting, cancelAccepting := context.WithCancel(ctx)
	defer cancelAccepting()
	go g.accept(accepting, listener)
	// Started here rather than on the first rejection so its lifetime is
	// exactly this call's: a goroutine that outlived Serve would keep asking
	// LND about a guard that has already exited.
	go g.probeRotation(accepting)

	g.log.Info("guard listening", "socket", socketPath)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.rotated:
		if err := g.sleep(ctx, RotationExitDelay); err != nil {
			return err
		}
		return ErrMacaroonRotated
	}
}

// accept runs until the listener is closed, which Serve's own deferred Close
// does on every return — including the rotation exit. ctx is here only to tell
// a deliberate shutdown from a real accept failure.
func (g *Guard) accept(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				g.log.Warn("guard socket accept failed", "error", err.Error())
			}
			return
		}
		go g.serveConn(ctx, conn)
	}
}

// serveConn handles one request and closes. The API is four small calls; there
// is nothing to gain from multiplexing and a great deal of state to get wrong.
func (g *Guard) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(socketTimeout))

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		g.writeResponse(conn, Response{Error: fmt.Sprintf("guard: unreadable request: %v", err)})
		return
	}
	g.writeResponse(conn, g.Handle(ctx, req))
}

func (g *Guard) writeResponse(conn net.Conn, resp Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		g.log.Warn("guard could not answer a request", "error", err.Error())
	}
}
