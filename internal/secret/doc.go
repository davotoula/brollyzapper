// Package secret holds the one redacting type every secret-bearing field in the
// codebase is built from, so no secret can serialise itself into a log line
// (spec §12). Amendment to the §3 layout, recorded in that section.
package secret
