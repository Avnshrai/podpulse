package logsev

import "testing"

func TestClassifyJSON(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{`{"level":"info","msg":"started"}`, Info},
		{`{"level":"error","msg":"db down"}`, Error},
		{`{"severity":"WARN","message":"deprecated"}`, Warn},
		{`{"lvl":"debug","msg":"x"}`, Debug},
		{`{"@level":"fatal","msg":"oom"}`, Fatal},
	}
	for _, c := range cases {
		if got := Classify(c.in); got != c.want {
			t.Errorf("%s: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestClassifyLogfmt(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{`time=2024 level=info msg="GET /foo"`, Info},
		{`level=error caller=foo.go:1 msg="boom"`, Error},
		{`lvl=warn message="deprecated"`, Warn},
	}
	for _, c := range cases {
		if got := Classify(c.in); got != c.want {
			t.Errorf("%s: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestClassifyBracketed(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{`[INFO] starting up`, Info},
		{`[ERROR] connection refused`, Error},
		{`2024-01-01 [WARN] deprecated`, Warn},
		{`INFO: server listening`, Info},
		{`ERROR redis-master:6379 unreachable`, Error},
	}
	for _, c := range cases {
		if got := Classify(c.in); got != c.want {
			t.Errorf("%s: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestClassifyKeywords(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{`Error: connect ECONNREFUSED 127.0.0.1:6379`, Error},
		{`panic: nil pointer dereference`, Fatal},
		{`Traceback (most recent call last)`, Error},
		{`Connection refused dialing redis-master`, Error},
		{`Warning: too many open files`, Warn},
		{`GET /api/users 200 12ms`, Unknown},
		{`cache hit ttl=300`, Unknown},
	}
	for _, c := range cases {
		if got := Classify(c.in); got != c.want {
			t.Errorf("%q: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !Error.AtLeast(Warn) {
		t.Error("Error >= Warn should be true")
	}
	if Info.AtLeast(Warn) {
		t.Error("Info >= Warn should be false")
	}
}
