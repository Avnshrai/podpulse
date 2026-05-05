package redact

import (
	"strings"
	"testing"
)

// All test fixtures here are SYNTHETIC — built to match each rule's
// regex shape but containing only fake characters. Never paste real
// secrets here; GitHub secret-scanning will block the push.

func TestRedactsCommonSecretShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // substring that must appear in output
	}{
		{
			name: "stripe-key",
			in:   "stripe key sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000000000",
			want: "<*REDACTED:stripe-key*>",
		},
		{
			name: "stripe-whsec",
			in:   "stripe webhook whsec_FAKEFAKEFAKEFAKEFAKE0000",
			want: "<*REDACTED:stripe-whsec*>",
		},
		{
			name: "hubspot-pat",
			in:   "hubspot pat-na1-FAKE0000-FAKE-FAKE-FAKE-FAKE00000000",
			want: "<*REDACTED:hubspot-pat*>",
		},
		{
			name: "redis-uri",
			in:   "uri rediss://:FAKEPASSWORDFAKE0000=@redis.example.invalid:6380",
			want: "<*REDACTED:redis-uri*>",
		},
		{
			name: "mongo-uri",
			in:   "mongodb://user:fakepass@mongo.example.invalid:27017/db",
			want: "<*REDACTED:mongo-uri*>",
		},
		{
			name: "kv-secret",
			in:   `admin_password: "FakeP@ssw0rd"`,
			want: "<*REDACTED:secret*>",
		},
		{
			name: "jwt",
			in:   "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.FAKE_SIGNATURE_PADDING_AAAAA",
			want: "<*REDACTED:jwt*>",
		},
		{
			name: "aws-access-key",
			in:   "AWS key AKIAIOSFODNN7EXAMPLE rotated",
			want: "<*REDACTED:aws-access-key*>",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := Line(c.in)
			if !strings.Contains(out, c.want) {
				t.Errorf("input %q\n  got:  %s\n  want substring: %s", c.in, out, c.want)
			}
		})
	}
}

func TestPassthroughForPlainText(t *testing.T) {
	in := "GET /api/users 200 12ms"
	if out := Line(in); out != in {
		t.Errorf("plain text was modified: %q -> %q", in, out)
	}
}
