package api

// LogLevelNamesForTest is the option list the Settings page ranges over, so the
// external test can assert the rendered select against the ONE statement of it
// rather than against a re-typed copy (0vk.38).
//
// A re-typed copy is exactly what the retired pin was: two lists compared, which
// reports drift instead of preventing it. Reaching the real list means the test
// asserts that the template gets there, which is the claim worth holding.
func LogLevelNamesForTest() []string { return logLevelNames() }
