// Package logging is the §12 seam: the slog wiring both binaries share, the
// runtime-adjustable level, the audit-event vocabulary, and the Auditor that
// writes a security event to the log and the durable trail together.
//
// It deliberately depends on nothing but the standard library, so the guard —
// which has no database — can use it without linking one.
package logging
