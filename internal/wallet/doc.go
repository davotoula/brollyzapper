// Package wallet owns the balance. It implements the Spender seam — reserve,
// settle, reverse — and the working ceiling; nothing outside this package may
// consult or mutate the balance (spec §3, §5).
package wallet
