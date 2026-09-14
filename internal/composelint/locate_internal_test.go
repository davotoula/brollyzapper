package composelint

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// A comment the parser reported and the source does not carry is REPORTED, not
// dropped: Parse refuses the document on it. The two sources differ here only so
// the placement has something to fail on; in Parse they are one file.
func TestAnUnplaceableCommentIsReported(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("# an INTERIM note\nservices: {}\n"), &root); err != nil {
		t.Fatal(err)
	}
	comments, unplaced := locateComments(&root, []byte("services: {}\n"))
	if unplaced != "# an INTERIM note" {
		t.Errorf("unplaced = %q with comments %+v; a comment that matched no line was dropped silently",
			unplaced, comments)
	}
}
