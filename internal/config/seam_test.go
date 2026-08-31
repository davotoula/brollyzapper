package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/config"
)

// Spec §3 and §6: the only copy of admin.macaroon lives in the guard. The
// server not having a field for it is the structural half of that — it cannot
// be configured to hold one, documentation notwithstanding.
func TestServerConfigHasNoMacaroonField(t *testing.T) {
	for _, f := range fieldNames(reflect.TypeOf(config.Server{})) {
		if strings.Contains(strings.ToLower(f), "macaroon") {
			t.Errorf("config.Server has field %q; the server must not be configurable "+
				"with a macaroon (spec §3, §6)", f)
		}
	}
}

// The control for the test above: if config.Guard ever loses its macaroon field,
// the assertion on config.Server has stopped meaning anything.
func TestGuardConfigDoesHaveTheMacaroonField(t *testing.T) {
	for _, f := range fieldNames(reflect.TypeOf(config.Guard{})) {
		if strings.Contains(strings.ToLower(f), "macaroon") {
			return
		}
	}
	t.Error("config.Guard has no macaroon field; the guard is the only holder of admin.macaroon")
}

// Spec §19: the app takes generic settings and the Umbrel package translates.
// This is that seam, asserted. Only non-test files are scanned — this file
// necessarily contains the very tokens it forbids.
func TestPackageContainsNoDeploymentSpecificNames(t *testing.T) {
	forbidden := []string{"UMBREL_", "APP_", "app-data"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package dir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		scanned++
		for lineNo, line := range strings.Split(string(src), "\n") {
			for _, tok := range forbidden {
				if strings.Contains(line, tok) {
					t.Errorf("%s:%d contains %q — internal/config must stay free of "+
						"deployment-specific names (spec §19): %s", name, lineNo+1, tok, strings.TrimSpace(line))
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no files; the check is not actually running")
	}
}

func fieldNames(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		out = append(out, t.Field(i).Name)
	}
	return out
}
