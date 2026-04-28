package redact

import (
	"strings"
	"testing"
)

func TestRedactsCommonSecretShapes(t *testing.T) {
	cases := []struct {
		in   string
		want string // substring that must appear in output
		nope string // substring that must NOT appear in output
	}{
		{
			in:   "stripe key sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000000000",
			want: "<*REDACTED:stripe-key*>",
			nope: "sk_test_FAKEXXX",
		},
		{
			in:   "stripe webhook whsec_FAKEFAKEFAKEFAKEFAKE0000",
			want: "<*REDACTED:stripe-whsec*>",
			nope: "whsec_FAKEXX",
		},
		{
			in:   "hubspot pat-na1-FAKE0000-FAKE-FAKE-FAKE-FAKE00000000",
			want: "<*REDACTED:hubspot-pat*>",
			nope: "pat-na1-FAKE000",
		},
		{
			in:   "uri rediss://:FAKEPASSWORDFAKE0000=@redis.example.invalid:6380",
			want: "<*REDACTED:redis-uri*>",
			nope: "FAKEPASSWO",
		},
		{
			in:   "mongodb://user:fakepass@mongo.example.invalid:27017/sigma_db",
			want: "<*REDACTED:mongo-uri*>",
			nope: ":password@",
		},
		{
			in:   `coredge_admin_password: "FakeP@ssw0rd"`,
			want: "<*REDACTED:secret*>",
			nope: "FakeP@ssw0rd",
		},
		{
			in:   "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.FAKE_SIGNATURE_PADDING_AAAAA",
			want: "<*REDACTED:jwt*>",
			nope: "eyJhbGciOiJIUzI1NiJ9",
		},
		{
			in:   "AWS key AKIAIOSFODNN7EXAMPLE rotated",
			want: "<*REDACTED:aws-access-key*>",
			nope: "AKIAIOSFODNN7EXAMPLE",
		},
	}
	for _, c := range cases {
		out := Line(c.in)
		if !strings.Contains(out, c.want) {
			t.Errorf("input %q\n  got:  %s\n  want substring: %s", c.in, out, c.want)
		}
		if c.nope != "" && strings.Contains(out, c.nope) {
			t.Errorf("input %q\n  got:  %s\n  must not contain: %s", c.in, out, c.nope)
		}
	}
}

func TestPassthroughForPlainText(t *testing.T) {
	in := "GET /api/users 200 12ms"
	if out := Line(in); out != in {
		t.Errorf("plain text was modified: %q -> %q", in, out)
	}
}
