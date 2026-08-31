package api

import (
	"errors"
	"net/http"
)

// MaxFormBytes bounds an admin form body (review L6).
//
// Every form this app serves is a handful of short fields; the largest is a
// nostr key import. 64KiB is roughly a thousand times the biggest legitimate
// submission, which is the right side to err on — the limit exists to stop an
// unbounded read, not to police field lengths.
const MaxFormBytes = 64 << 10

// readForm parses a form body under MaxFormBytes, answering the caller itself
// when it cannot.
//
// It exists because there are exactly two places that read a form — the login
// POST and the admin group's CSRF gate — and both were calling ParseForm on
// r.Body directly, which reads as much as the caller sends. One function so the
// cap cannot be applied to one of them and forgotten on the other, and so the
// distinction between "too big" and "malformed" is drawn once: an oversized
// body is 413 and a truncated or mis-encoded one is 400, and answering 400 to
// both would tell an operator with a big form to check their syntax.
//
// It must be called BEFORE anything that depends on the parsed form — on the
// admin path that means before the CSRF comparison, because ParseForm is what
// reads the token, so a size check placed after it has already done the read it
// was meant to prevent.
func readForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
	err := r.ParseForm()
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "form too large", http.StatusRequestEntityTooLarge)
		return false
	}
	http.Error(w, "unreadable form", http.StatusBadRequest)
	return false
}
