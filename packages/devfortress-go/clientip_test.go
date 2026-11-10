package devfortress

import "testing"

func TestPrecedenceIsForwardedForThenRealIPThenSocket(t *testing.T) {
	cases := []struct{ forwardedFor, realIP, remoteAddr, want string }{
		{"203.0.113.9, 10.0.0.1", "198.51.100.1", "192.0.2.1", "203.0.113.9"},
		{"", "198.51.100.1", "192.0.2.1", "198.51.100.1"},
		{"", "", "192.0.2.1", "192.0.2.1"},
		{"", "", "", "0.0.0.0"},
	}
	for _, c := range cases {
		if got := ResolveClientIP(c.forwardedFor, c.realIP, c.remoteAddr); got != c.want {
			t.Errorf("ResolveClientIP(%q, %q, %q) = %q, want %q", c.forwardedFor, c.realIP, c.remoteAddr, got, c.want)
		}
	}
}

func TestAnEntryThatIsNotAnIPIsSkipped(t *testing.T) {
	if got := ResolveClientIP("unknown", "198.51.100.1", "192.0.2.1"); got != "198.51.100.1" {
		t.Errorf("got %q", got)
	}
	if got := ResolveClientIP("2001:db8::1", "", ""); got != "2001:db8::1" {
		t.Errorf("got %q", got)
	}
	if got := ResolveClientIP("<script>", "nope", "x"); got != "0.0.0.0" {
		t.Errorf("got %q", got)
	}
}
