// Package logsev classifies a single log line into a severity bucket.
//
// This is how the big players cut the firehose down to actionable
// signal:
//
//   Datadog Agent: parses JSON for level/severity/lvl, falls back to
//                  bracketed [INFO] / [ERROR] and syslog priority.
//   Splunk:        regex extracts based on per-sourcetype patterns.
//   Elastic ECS:   processors map common formats to log.level.
//   Loki:          Grafana's parser libraries detect levels in logfmt
//                  and JSON.
//
// We do the same thing in pure Go: a fast multi-pass classifier that
// recognises the formats real-world apps emit (Go zap/zerolog, Python
// logging, Node bunyan/pino, JVM log4j/SLF4J, plain text printf).
package logsev

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Severity is the canonical level. Higher = more important.
type Severity int

const (
	Trace Severity = iota
	Debug
	Info
	Warn
	Error
	Fatal
	Unknown // lines we can't classify; treated as Info by callers
)

func (s Severity) String() string {
	switch s {
	case Trace:
		return "trace"
	case Debug:
		return "debug"
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Error:
		return "error"
	case Fatal:
		return "fatal"
	}
	return "unknown"
}

// AtLeast returns true if s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s >= min }

// Classify returns the severity of the line. Cheap (regex + small
// scans), safe for hot-path use.
func Classify(line string) Severity {
	if line == "" {
		return Unknown
	}

	// 1. JSON line — parse once and look at the conventional level keys.
	if strings.HasPrefix(line, "{") {
		if s, ok := classifyJSON(line); ok {
			return s
		}
	}

	// 2. logfmt: `... level=info ...` or `... lvl=info ...`.
	if s, ok := classifyLogfmt(line); ok {
		return s
	}

	// 3. Bracketed:    `[INFO]`, `[ERROR]`, `[WARN]`, `[DEBUG]`
	//    Prefixed:     `INFO:`, `ERROR -`, `[2024-01-01] [ERROR]`
	if s, ok := classifyBracketed(line); ok {
		return s
	}

	// 4. Keyword fallback. Conservative: only fire on strong signals.
	if s, ok := classifyKeywords(line); ok {
		return s
	}

	return Unknown
}

// --- JSON ---

var jsonLevelKeys = []string{"level", "severity", "lvl", "log_level", "loglevel", "@level"}

func classifyJSON(line string) (Severity, bool) {
	// Cheap up-front check: bail out if it's not a small object.
	if len(line) > 16<<10 {
		return Unknown, false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return Unknown, false
	}
	for _, k := range jsonLevelKeys {
		if v, ok := m[k]; ok {
			if s, ok := stringToSeverity(stringify(v)); ok {
				return s, true
			}
		}
	}
	// Some structured loggers (zap) emit numeric level; check for it.
	if v, ok := m["level"]; ok {
		if n, ok := numberToInt(v); ok {
			return numericToSeverity(n), true
		}
	}
	return Unknown, false
}

// --- logfmt ---

var rxLogfmtLevel = regexp.MustCompile(`(?i)\b(?:level|lvl|log_level|severity)[\s:=]+["']?([A-Za-z]+)["']?`)

func classifyLogfmt(line string) (Severity, bool) {
	m := rxLogfmtLevel.FindStringSubmatch(line)
	if len(m) < 2 {
		return Unknown, false
	}
	return stringToSeverity(m[1])
}

// --- bracketed ---

var (
	rxBracket  = regexp.MustCompile(`\[(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|CRITICAL|CRIT|FATAL|EMERG|ALERT)\]`)
	rxLevelTag = regexp.MustCompile(`(?:^|\s)(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|ERR|CRITICAL|CRIT|FATAL|EMERG|ALERT)\b`)
)

func classifyBracketed(line string) (Severity, bool) {
	if m := rxBracket.FindStringSubmatch(line); len(m) > 1 {
		return stringToSeverity(m[1])
	}
	// Look only in the first ~120 chars to avoid keyword false positives
	// later in the message body.
	head := line
	if len(head) > 120 {
		head = head[:120]
	}
	if m := rxLevelTag.FindStringSubmatch(head); len(m) > 1 {
		return stringToSeverity(m[1])
	}
	return Unknown, false
}

// --- keyword fallback ---

// Strong error signals: stack traces, panics, uncaught exceptions.
var (
	rxPanic = regexp.MustCompile(`(?i)\b(panic|fatal error|stack overflow|segmentation fault|core dumped)\b`)
	rxStack = regexp.MustCompile(`(?i)\b(traceback \(most recent call last\)|exception in thread|unhandled (?:exception|error|rejection)|caused by:|java\.lang\.[A-Z]\w+Exception)`)
	rxExpl  = regexp.MustCompile(`(?i)\b(error|errored|failed|failure|exception|denied|refused|unreachable|timeout|timed out)\b`)
	rxWarn  = regexp.MustCompile(`(?i)\b(warning|warn|deprecated|retrying)\b`)
)

func classifyKeywords(line string) (Severity, bool) {
	switch {
	case rxPanic.MatchString(line):
		return Fatal, true
	case rxStack.MatchString(line):
		return Error, true
	case rxExpl.MatchString(line):
		return Error, true
	case rxWarn.MatchString(line):
		return Warn, true
	}
	return Unknown, false
}

// --- helpers ---

func stringToSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return Trace, true
	case "debug", "dbg":
		return Debug, true
	case "info", "informational", "notice":
		return Info, true
	case "warn", "warning":
		return Warn, true
	case "err", "error":
		return Error, true
	case "fatal", "panic", "crit", "critical", "alert", "emerg", "emergency":
		return Fatal, true
	}
	return Unknown, false
}

// numericToSeverity interprets common integer level conventions.
// Most libraries: smaller = more verbose. zap uses negative for debug.
// We pick a defensible mapping that covers logr/zap/syslog.
func numericToSeverity(n int) Severity {
	switch {
	case n <= -1:
		return Debug
	case n == 0:
		return Info
	case n == 1, n == 2:
		return Warn
	case n == 3, n == 4:
		return Error
	case n >= 5:
		return Fatal
	}
	return Info
}

func stringify(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return ""
	}
	return ""
}

func numberToInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	}
	return 0, false
}
