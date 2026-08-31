// Package guard implements the credential broker: the unix socket protocol
// the server speaks, the bake/revoke operations, the rolling hard spend cap and
// (from P4) the LND RPC middleware client. It is the sole holder of
// admin.macaroon and it never listens on a network socket (spec §3, §6).
package guard
