// Package tail tails CRI container log files under /var/log/pods and
// emits one parsed log line per callback invocation.
//
// CRI log format (one record per line):
//
//	2024-01-15T10:30:45.123456789Z stdout F message text here
//	└──────── timestamp ──────────┘ ┬────┘ ┬ └─── message ───┘
//	                                stream tag (P=partial, F=full)
//
// We coalesce P-tagged lines until the next F so callers always see
// one logical message at a time.
package tail

import (
	"strings"
	"time"
)

// Record is one parsed log line.
type Record struct {
	Timestamp time.Time
	Stream    string // stdout | stderr
	Message   string
}

// parseCRI parses a single line of CRI-formatted log text. Returns
// ok=false on a malformed line; the caller should drop those.
func parseCRI(line string) (Record, bool) {
	// timestamp <space> stream <space> tag <space> message
	a := strings.IndexByte(line, ' ')
	if a < 0 {
		return Record{}, false
	}
	b := strings.IndexByte(line[a+1:], ' ')
	if b < 0 {
		return Record{}, false
	}
	b += a + 1
	c := strings.IndexByte(line[b+1:], ' ')
	if c < 0 {
		return Record{}, false
	}
	c += b + 1

	tsRaw := line[:a]
	stream := line[a+1 : b]
	// tag := line[b+1:c]   // P or F — surfaced via partialBuf in the caller.
	msg := line[c+1:]

	ts, err := time.Parse(time.RFC3339Nano, tsRaw)
	if err != nil {
		// Some kubelets emit lower-precision timestamps. Try RFC3339.
		ts, err = time.Parse(time.RFC3339, tsRaw)
		if err != nil {
			return Record{}, false
		}
	}
	if stream != "stdout" && stream != "stderr" {
		return Record{}, false
	}

	return Record{Timestamp: ts, Stream: stream, Message: msg}, true
}

// criTag returns 'F' (full) or 'P' (partial) for a line, or 0 if the
// line is malformed.
func criTag(line string) byte {
	a := strings.IndexByte(line, ' ')
	if a < 0 {
		return 0
	}
	b := strings.IndexByte(line[a+1:], ' ')
	if b < 0 {
		return 0
	}
	b += a + 1
	if len(line) < b+2 {
		return 0
	}
	return line[b+1]
}
