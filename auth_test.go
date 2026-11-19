package main

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Which client addresses count as "on the LAN".
func TestIsLAN(t *testing.T) {
	for addr, want := range map[string]bool{
		"192.168.188.7:1": true, "10.0.0.1:1": true, "172.16.0.1:1": true, "127.0.0.1:1": true, "[::1]:1": true,
		"[::ffff:192.168.1.1]:1": true, "[fd00::1]:1": true, "[fe80::1]:1": true, "169.254.1.1:1": true,
		"8.8.8.8:1": false, "172.32.0.1:1": false, "[2001:db8::1]:1": false, "[::ffff:8.8.8.8]:1": false,
		"garbage": false, "192.168.1.1": false, ":1": false,
	} {
		if got := isLAN(addr); got != want {
			t.Errorf("isLAN(%q) = %v, want %v", addr, got, want)
		}
	}
}

// Which requests count as made by HomeStream's own page.
func TestSameOrigin(t *testing.T) {
	for _, tc := range []struct {
		site, origin string
		want         bool
	}{
		{"", "", true}, {"same-origin", "", true}, {"same-origin", "https://evil.example", true},
		{"cross-site", "", false}, {"same-site", "", false}, {"none", "", false},
		{"", "https://example.com", true}, {"", "http://example.com", false}, {"", "https://example.com:8443", false}, {"", "null", false},
	} {
		r := httptest.NewRequest("POST", "https://example.com/api/login", nil)
		if tc.site != "" {
			r.Header.Set("Sec-Fetch-Site", tc.site)
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if got := sameOrigin(r); got != tc.want {
			t.Errorf("Sec-Fetch-Site %q, Origin %q: sameOrigin = %v, want %v", tc.site, tc.origin, got, tc.want)
		}
	}
}

// Session tokens: only an untouched, unexpired one from this server is valid.
func TestSession(t *testing.T) {
	s, _ := newServer(t.TempDir(), "pw")
	other, _ := newServer(t.TempDir(), "pw") // a restarted server has a new secret
	future := time.Now().Add(time.Hour).Unix()
	good := s.sign(future)
	tampered := strings.Replace(good, strconv.FormatInt(future, 10), strconv.FormatInt(future+1, 10), 1)
	for name, tc := range map[string]struct {
		tok  string
		want bool
	}{
		"good": {good, true}, "expired": {s.sign(time.Now().Add(-time.Hour).Unix()), false},
		"tampered": {tampered, false}, "garbage": {"x", false}, "empty": {"", false},
		"no signature": {strconv.FormatInt(future, 10) + ".", false}, "other server": {other.sign(future), false},
	} {
		if got := s.valid(tc.tok); got != tc.want {
			t.Errorf("%s: valid = %v, want %v", name, got, tc.want)
		}
	}
}

// Wrong passwords are handled one at a time, each taking the full delay, so
// opening many connections does not speed up guessing.
func TestLoginRateLimit(t *testing.T) {
	s, _ := newServer(t.TempDir(), "pw")
	s.delay = 50 * time.Millisecond
	h := s.routes()
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); do(h, "POST", "/api/login", "wrong", nil) }()
	}
	wg.Wait()
	if d := time.Since(start); d < 4*s.delay {
		t.Errorf("4 parallel wrong passwords took %v, want at least %v", d, 4*s.delay)
	}
}
