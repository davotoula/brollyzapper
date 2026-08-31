// Package nwc is §8's NIP-47 wallet service: it subscribes to each connection's
// relay, authorizes and decrypts requests, answers them idempotently, and
// publishes encrypted responses.
//
// It holds no credential of its own and touches no macaroon. Since d24.4 it can
// pay, and everything it can do about money it does through §8's rejection
// ladder and the wallet's Spender seam behind it — which is where §5's ceiling
// and both freezes live. This package can refuse a payment on its own; it cannot
// authorise one past a limit it did not set.
package nwc
