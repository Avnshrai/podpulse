// Package redact masks high-confidence secret patterns out of log lines
// before they're templated by Drain3 and stored as samples on anomalies.
//
// The redactor is a single regex sweep — fast (one pass over the input)
// and conservative (it errs on the side of redaction). Templates that
// would otherwise embed a literal Stripe / HubSpot / JWT / Redis URL
// password become "<*REDACTED:kind*>".
//
// This is not a complete DLP solution — long-tail secrets (proprietary
// API keys, custom tokens) still need a per-tenant rule list — but it
// catches the common shapes that show up in printf-style env-dump logs.
package redact

import "regexp"

// rule pairs a pattern with the placeholder that replaces it.
type rule struct {
	re    *regexp.Regexp
	repl  string
}

// Order matters: more specific patterns first (e.g. mongodb:// must be
// recognized before any generic "long token" rule).
var rules = []rule{
	{regexp.MustCompile(`(?i)\b(mongodb(\+srv)?:\/\/)[^:\/\s]+:[^@\s]+@`), "$1<*REDACTED:mongo-uri*>@"},
	{regexp.MustCompile(`(?i)\b(rediss?:\/\/)[^:\/\s]*:[^@\s]+@`), "$1<*REDACTED:redis-uri*>@"},
	{regexp.MustCompile(`(?i)\b(amqps?:\/\/)[^:\/\s]+:[^@\s]+@`), "$1<*REDACTED:amqp-uri*>@"},
	{regexp.MustCompile(`(?i)\b(postgres(?:ql)?:\/\/)[^:\/\s]+:[^@\s]+@`), "$1<*REDACTED:pg-uri*>@"},
	{regexp.MustCompile(`(?i)\bsk_(?:test|live)_[A-Za-z0-9]{20,}\b`), "<*REDACTED:stripe-key*>"},
	{regexp.MustCompile(`(?i)\bwhsec_[A-Za-z0-9]{20,}\b`), "<*REDACTED:stripe-whsec*>"},
	{regexp.MustCompile(`(?i)\bpat-[a-z0-9]+-[A-Za-z0-9-]{20,}\b`), "<*REDACTED:hubspot-pat*>"},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), "<*REDACTED:slack-token*>"},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`), "<*REDACTED:github-token*>"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "<*REDACTED:aws-access-key*>"},
	{regexp.MustCompile(`\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b`), "<*REDACTED:jwt*>"},
	// Generic "Authorization: Bearer ...".
	{regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._-]{16,}`), "$1<*REDACTED:bearer*>"},
	// Generic password / token / api_key in key=value form.
	{regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*)["']?[^"'\s,}]{6,}["']?`), `${1}"<*REDACTED:secret*>"`},
}

// Line returns the input with secret-shaped substrings replaced.
func Line(s string) string {
	if s == "" {
		return s
	}
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}
