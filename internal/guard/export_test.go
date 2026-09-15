package guard

import "os"

// SetCredentialWriter replaces how g writes to the credential volume, so a test
// can interrupt a bake between its writes (2o1).
func SetCredentialWriter(g *Guard, write func(path string, data []byte, mode os.FileMode) error) {
	g.writeCredential = write
}
