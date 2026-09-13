package composelint

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Key is one mapping key: the line it is on and the comment block written
// directly above it, which yaml.v3 attaches to the key node as its HeadComment.
type Key struct {
	Line    int
	Comment string
}

// Key finds the key at path — "services", "server", "user" — and reports whether
// every step of the path was a mapping holding the next name.
//
// THE PARSER SAYS WHICH COMMENT BELONGS TO WHICH LINE. A text reading takes the
// first `user:` found below a `guard:`, and reads the server's comment the day
// the guard's own user: line is deleted.
func (d *Document) Key(path ...string) (Key, bool) {
	k, _, ok := d.entry(path)
	if !ok {
		return Key{}, false
	}
	return Key{Line: k.Line, Comment: k.HeadComment}, true
}

// entry is the key and value nodes at path. The document node's first child is
// the top-level mapping.
func (d *Document) entry(path []string) (key, value *yaml.Node, ok bool) {
	if len(d.root.Content) == 0 || len(path) == 0 {
		return nil, nil, false
	}
	value = d.root.Content[0]
	for _, name := range path {
		key, value = mappingEntry(value, name)
		if key == nil {
			return nil, nil, false
		}
	}
	return key, value, true
}

// mappingEntry is one key of a mapping node and its value; nil for a nil or
// non-mapping node, so a chain of lookups fails once, at the end.
func mappingEntry(node *yaml.Node, key string) (k, v *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i], node.Content[i+1]
		}
	}
	return nil, nil
}

// Between is what sits between two keys of one mapping.
type Between struct {
	// First and Second are the two keys' lines.
	First, Second int
	// Entries are the keys strictly between them, in document order, each with
	// its line — settings, never comments or blank lines, which are not entries.
	Entries []Scalar
}

// KeysBetween answers "what sits between these two keys" for the mapping at
// mapping, from the document's own order.
//
// THE ONE PLACE A "BETWEEN TWO KEYS" READING IS LEGITIMATE (umbrel's
// ADMIN_PASSWORD_MANAGED adjacency): a decoded map has no order, and the check is
// about order. It used to read that off the raw lines, where it had to decide by
// hand that `#` lines and blanks do not count; in the node tree comments and
// blank lines are not entries at all, so there is nothing to exempt.
//
// Second before First is reported through the line numbers, not as an error:
// the caller's message for that case names both lines.
func (d *Document) KeysBetween(mapping []string, first, second string) (Between, error) {
	_, node, ok := d.entry(mapping)
	if !ok || node.Kind != yaml.MappingNode {
		return Between{}, fmt.Errorf("%s has no mapping at %s", d.path, strings.Join(mapping, "."))
	}
	firstAt, secondAt := -1, -1
	for i := 0; i+1 < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case first:
			firstAt = i
		case second:
			secondAt = i
		}
	}
	for _, missing := range []struct {
		at   int
		name string
	}{{firstAt, first}, {secondAt, second}} {
		if missing.at < 0 {
			return Between{}, fmt.Errorf("no key in %s at %s sets %q", d.path, strings.Join(mapping, "."), missing.name)
		}
	}
	out := Between{First: node.Content[firstAt].Line, Second: node.Content[secondAt].Line}
	for i := firstAt + 2; i < secondAt; i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		out.Entries = append(out.Entries, Scalar{Value: k.Value + ": " + v.Value, Line: k.Line})
	}
	return out, nil
}

// NetworkSettings is one service's entry in the mapping form of `networks:`.
type NetworkSettings struct {
	IPv4    string   `yaml:"ipv4_address"`
	Aliases []string `yaml:"aliases"`
}

// Networks is a service's networks in the mapping form, which is the only form
// that can carry an address or an alias. The sequence form — `networks:
// [brolly]` — is an error, which is the right answer for every caller: they are
// asking for something only the mapping form holds. A service with no networks:
// at all has none, which is empty rather than an error — what the caller asked
// about is then simply not there, and its own message says so.
func (d *Document) Networks(service string) (map[string]NetworkSettings, error) {
	_, node, ok := d.entry([]string{"services", service, "networks"})
	if !ok {
		return nil, nil
	}
	var out map[string]NetworkSettings
	if err := node.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Ports is a service's `ports:` in the short string form. The long mapping form
// is an error rather than a guess; no ports: at all is empty.
func (d *Document) Ports(service string) ([]string, error) {
	_, node, ok := d.entry([]string{"services", service, "ports"})
	if !ok {
		return nil, nil
	}
	var out []string
	if err := node.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// SplitPort reads compose's short port syntax — [ip:]host:container[/proto] —
// with the host side either a number or `${VAR:-number}`, in which case the
// default is returned. Any other spelling is an error rather than a guess.
func SplitPort(mapping string) (host, container string, err error) {
	mapping, _, _ = strings.Cut(mapping, "/")
	cut := strings.LastIndex(mapping, ":")
	if cut < 0 {
		return "", "", fmt.Errorf("port %q publishes no host port", mapping)
	}
	hostSide, container := mapping[:cut], mapping[cut+1:]
	if m := defaultedPortRE.FindStringSubmatch(hostSide); m != nil {
		return m[1], container, nil
	}
	if i := strings.LastIndex(hostSide, ":"); i >= 0 {
		hostSide = hostSide[i+1:] // an ip: prefix
	}
	if !numericRE.MatchString(hostSide) || !numericRE.MatchString(container) {
		return "", "", fmt.Errorf("port %q is not a spelling this lint reads", mapping)
	}
	return hostSide, container, nil
}

var (
	defaultedPortRE = regexp.MustCompile(`^\$\{[A-Z_][A-Z0-9_]*:-([0-9]+)\}$`)
	numericRE       = regexp.MustCompile(`^[0-9]+$`)
)

// CommandLine is a service's `command:`, which compose accepts in two spellings:
// a YAML list, one argument per item, or a single string it splits like a shell.
// A TYPE, so a caller's own struct decodes it in place.
//
// BOTH DECODE, rather than []string refusing the string form. A []string field
// makes a string `command:` on ANY service a decode error that fails every test
// over a spelling none of them is about. The string form is split on whitespace,
// which is not compose's shlex: a quoted argument containing a space comes back
// in pieces. The arguments asked about are `--flag=value` with no space in them,
// so that can only split an argument nobody is looking for. What would reopen
// it: a check that needs a quoted argument whole.
type CommandLine []string

// UnmarshalYAML decodes either spelling.
func (c *CommandLine) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*c = strings.Fields(value.Value)
		return nil
	}
	var args []string
	if err := value.Decode(&args); err != nil {
		return err
	}
	*c = args
	return nil
}

// locateComments is every comment the parser kept, each placed on its line.
//
// yaml.v3 records comments on nodes — HeadComment, LineComment, FootComment —
// but not the lines they sit on, and a check that names a line in its message
// needs one. So each comment line the PARSER reported is found in the source,
// in order, starting from the node it is attached to. Only text the parser
// already classified as a comment is placed, so a `#` inside a quoted value
// cannot become one. The source is read here and not kept.
func locateComments(root *yaml.Node, src []byte) []Comment {
	lines := strings.Split(string(bytes.ReplaceAll(src, []byte("\r\n"), []byte("\n"))), "\n")
	used := make([]bool, len(lines))
	var out []Comment
	place := func(text string, from int, step int) {
		for i := from; i >= 0 && i < len(lines); i += step {
			if !used[i] && isCommentLine(lines[i], text) {
				used[i] = true
				out = append(out, Comment{Text: text, Line: i + 1})
				return
			}
		}
	}
	walk(root, func(n *yaml.Node) {
		start := max(n.Line-1, 0)
		// A head comment ends above its node, so it is searched upwards,
		// last line first.
		head := commentLines(n.HeadComment)
		for i := len(head) - 1; i >= 0; i-- {
			place(head[i], start, -1)
		}
		for _, text := range commentLines(n.LineComment) {
			place(text, start, +1)
		}
		for _, text := range commentLines(n.FootComment) {
			place(text, start, +1)
		}
	})
	sortComments(out)
	return out
}

// commentLines splits one of yaml.v3's comment fields into its non-blank lines.
func commentLines(block string) []string {
	var out []string
	for _, line := range strings.Split(block, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// isCommentLine reports whether source line carries comment text: the whole
// line, or its tail after code.
func isCommentLine(line, text string) bool {
	return strings.HasSuffix(strings.TrimRight(line, " \t"), text)
}

func sortComments(c []Comment) {
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j].Line < c[j-1].Line; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}
