// Package drain3 is a pure-Go implementation of the Drain log-template
// extraction algorithm (He et al., ICWS 2017). It clusters log lines into
// templates by:
//
//  1. Splitting on whitespace into tokens.
//  2. Bucketing by token count.
//  3. Walking a fixed-depth prefix tree keyed by literal tokens (variable
//     positions are kept as "<*>" placeholders).
//  4. At the leaf, finding the best template by token-similarity ratio
//     and updating it: positions that disagree become "<*>".
//
// The implementation is intentionally minimal — enough to anchor the
// detector's "new template seen for this workload+image" signal. Numeric-
// looking tokens are pre-masked so trivial varying values (counts, ports,
// timestamps, IDs) collapse before tree descent.
package drain3

import (
	"strings"
	"sync"
	"unicode"
)

// Cluster is a learned log template plus the count of lines it has matched.
type Cluster struct {
	ID       int      `json:"id"`
	Template []string `json:"template"`
	Size     int      `json:"size"`
}

// Format renders the template as a single string for display.
func (c *Cluster) Format() string {
	return strings.Join(c.Template, " ")
}

// Miner is the Drain template miner. Goroutine-safe: a single Miner can
// be shared across ingest workers.
type Miner struct {
	mu          sync.Mutex
	maxDepth    int     // tree depth (excluding root + token-count level)
	simTh       float64 // similarity threshold to merge into an existing cluster
	maxChildren int     // max children per internal node before falling back to "<*>"

	// root[tokenCount][firstToken]... → []*Cluster at the leaf.
	root map[int]*node

	clusters []*Cluster
	nextID   int
}

type node struct {
	children map[string]*node
	clusters []*Cluster
}

// New returns a Miner with sensible defaults.
func New() *Miner {
	return &Miner{
		maxDepth:    4,
		simTh:       0.4,
		maxChildren: 100,
		root:        map[int]*node{},
	}
}

// Add ingests one log line and returns the cluster it was assigned to and
// whether the cluster is brand new (i.e. this is the first line that
// produced it).
func (m *Miner) Add(line string) (*Cluster, bool) {
	tokens := tokenize(line)
	if len(tokens) == 0 {
		return nil, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	root, ok := m.root[len(tokens)]
	if !ok {
		root = newNode()
		m.root[len(tokens)] = root
	}

	leaf := m.descend(root, tokens)

	if best, score := m.bestMatch(leaf, tokens); best != nil && score >= m.simTh {
		m.update(best, tokens)
		best.Size++
		return best, false
	}

	c := &Cluster{
		ID:       m.nextID,
		Template: append([]string(nil), tokens...),
		Size:     1,
	}
	m.nextID++
	leaf.clusters = append(leaf.clusters, c)
	m.clusters = append(m.clusters, c)
	return c, true
}

// Clusters returns a snapshot of all clusters learned so far.
func (m *Miner) Clusters() []*Cluster {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Cluster, len(m.clusters))
	copy(out, m.clusters)
	return out
}

func (m *Miner) descend(root *node, tokens []string) *node {
	cur := root
	for d := 0; d < m.maxDepth && d < len(tokens); d++ {
		t := tokens[d]
		if isVariable(t) {
			t = wildcard
		}
		next, ok := cur.children[t]
		if !ok {
			// If we already have many siblings, collapse to "<*>" to
			// keep the tree bounded.
			if len(cur.children) >= m.maxChildren {
				if w, ok := cur.children[wildcard]; ok {
					cur = w
					continue
				}
				w := newNode()
				cur.children[wildcard] = w
				cur = w
				continue
			}
			next = newNode()
			cur.children[t] = next
		}
		cur = next
	}
	return cur
}

func (m *Miner) bestMatch(leaf *node, tokens []string) (*Cluster, float64) {
	var (
		bestC *Cluster
		bestS float64
	)
	for _, c := range leaf.clusters {
		if len(c.Template) != len(tokens) {
			continue
		}
		s := similarity(c.Template, tokens)
		if s > bestS {
			bestS, bestC = s, c
		}
	}
	return bestC, bestS
}

func (m *Miner) update(c *Cluster, tokens []string) {
	for i := range c.Template {
		if c.Template[i] == wildcard {
			continue
		}
		if c.Template[i] != tokens[i] {
			c.Template[i] = wildcard
		}
	}
}

func newNode() *node { return &node{children: map[string]*node{}} }

const wildcard = "<*>"

// tokenize splits on whitespace and pre-masks tokens that look like
// numbers, ports, durations, or hex IDs. This keeps templates stable
// across trivial varying values.
func tokenize(s string) []string {
	fields := strings.Fields(s)
	for i, f := range fields {
		if isVariable(f) {
			fields[i] = wildcard
		}
	}
	return fields
}

func isVariable(t string) bool {
	if t == "" {
		return false
	}
	// Heuristic: any token containing a digit is treated as variable. This
	// is aggressive — IDs, timestamps, ports, and counts all collapse —
	// which is what we want for stable templates.
	for _, r := range t {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func similarity(a, b []string) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	n := 0
	for i := range a {
		if a[i] == b[i] || a[i] == wildcard || b[i] == wildcard {
			n++
		}
	}
	return float64(n) / float64(len(a))
}
