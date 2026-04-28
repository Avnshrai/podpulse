package tail

import "testing"

func TestParsePodPath(t *testing.T) {
	cases := []struct {
		in         string
		ns, pod, c string
		ok         bool
	}{
		{
			in:  "/var/log/pods/gpu-paas_dev-gpu-paas-comm-749794d7f9-m8k49_1da6faf0-ba98-4450-b8cd-1ed0955fd10f/gpu-paas-comm/0.log",
			ns:  "gpu-paas",
			pod: "dev-gpu-paas-comm-749794d7f9-m8k49",
			c:   "gpu-paas-comm",
			ok:  true,
		},
		{
			in:  "/var/log/pods/kube-system_coredns-12345_abcd/coredns/3.log",
			ns:  "kube-system",
			pod: "coredns-12345",
			c:   "coredns",
			ok:  true,
		},
		{in: "/etc/passwd", ok: false},
		{in: "/var/log/pods/badname/container/0.log", ok: false},
	}
	for _, c := range cases {
		got, ok := ParsePodPath(c.in)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Namespace != c.ns || got.Pod != c.pod || got.Container != c.c {
			t.Errorf("%s: got ns=%s pod=%s c=%s, want %s/%s/%s",
				c.in, got.Namespace, got.Pod, got.Container, c.ns, c.pod, c.c)
		}
	}
}
