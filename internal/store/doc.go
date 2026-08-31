// Package store owns the sqlite database: opening it, the embedded migrations
// for the §4 schema, and the queries over it. All amounts are msat stored as
// INTEGER (spec §4).
package store
