// Package config parses and validates the environment for both binaries and
// fails fast on malformed input. It carries only generic settings — no Umbrel
// paths, names or defaults — which is the seam that lets BrollyZapper run on any
// LND (spec §19).
package config
