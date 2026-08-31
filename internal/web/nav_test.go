package web_test

import (
	"strings"
	"testing"

	"github.com/davotoula/brollyzapper/internal/web"
)

func TestTheNavMarksThePageYouAreOn(t *testing.T) {
	r := newRenderer(t)
	var b strings.Builder
	if err := r.Render(&b, "node", web.PageData{Title: "Node"}); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	if !strings.Contains(out, `<a href="/node" class="here">`) {
		t.Error("the Node link is not marked as the current page; the nav cannot say where you are")
	}
	// The negative half is the one that matters: a marker on every link is the
	// same as a marker on none.
	if strings.Contains(out, `<a href="/security" class="here">`) {
		t.Error("a page that is NOT current is marked as current")
	}
}
