package api

import "net/http"

// HealthHandler reports whether the process can serve, and nothing else.
//
// Spec §3: "200 ok or 503 and nothing else — no version, no balance, no node
// state; it is reachable by anyone". ready deliberately does not consult LND:
// an unreachable node is a degraded state the admin UI explains, not an
// unhealthy container for an orchestrator to restart (§11 forbids crash loops).
func HealthHandler(ready func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("unavailable"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
}
