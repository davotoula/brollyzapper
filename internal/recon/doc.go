// Package recon runs the periodic node-versus-wallet sanity check and freezes
// spending on a shortfall (spec §5, §11).
//
// It reports; it never corrects. The balance is not silently rewritten — a
// correction is an explicit adjustment txn with a reason, made by the operator
// and visible in history.
package recon
