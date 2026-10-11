package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Which paths may be listed and served.
func TestAllowed(t *testing.T) {
	for rel, want := range map[string]bool{
		"Films/300.mp4": true, "a/b.MP3": true, "a/b [x].opus": true,
		"a/b.txt": false, "a/b.mp4.part": false, ".Trash-1000/x.mp4": false,
		"a/.hid/x.mp4": false, "lost+found/x.mp3": false, "": false, "a//b.mp4": false,
		"a/...title.mp4": true, "a/._junk.mp4": false, "../x.mp4": false,
	} {
		if got := allowed(rel); got != want {
			t.Errorf("allowed(%q) = %v, want %v", rel, got, want)
		}
	}
}

// Which client addresses count as "on the LAN".
func TestIsLAN(t *testing.T) {
	for addr, want := range map[string]bool{
		"192.168.188.7:1": true, "10.0.0.1:1": true, "127.0.0.1:1": true, "[::1]:1": true,
		"[::ffff:192.168.1.1]:1": true, "[fd00::1]:1": true, "[fe80::1]:1": true,
		"8.8.8.8:1": false, "[2001:db8::1]:1": false, "garbage": false,
	} {
		if got := isLAN(addr); got != want {
			t.Errorf("isLAN(%q) = %v, want %v", addr, got, want)
		}
	}
}

// testServer returns a server over a small library that holds one of each
// case: playable files, a text file, a hidden folder, lost+found and symlinks.
func testServer(t *testing.T) http.Handler {
	// The media root is a subfolder, so that ../secret.mp4 is a real media file
	// just outside it: the only thing keeping it private is the ".." handling.
	root := filepath.Join(t.TempDir(), "lib")
	for _, p := range []string{"a/b.mp4", "a/c.txt", ".hid/d.mp4", "lost+found/e.mp3", "f.MP3", "../secret.mp4"} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte("0123456789"), 0o644)
	}
	os.Symlink(filepath.Join(root, "a/c.txt"), filepath.Join(root, "link.mp4"))
	os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "dirlink"))
	s, err := newServer(root, "pw")
	if err != nil {
		t.Fatal(err)
	}
	s.delay = 0
	return s.routes()
}

// do sends one request from a LAN address and returns the answer. mod, if
// given, can change the request first, for example to add the session cookie.
func do(h http.Handler, method, target, body string, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.RemoteAddr = "192.168.1.5:1234"
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Session tokens: only an untouched, unexpired one is valid.
func TestSession(t *testing.T) {
	s, _ := newServer(t.TempDir(), "pw")
	future := time.Now().Add(time.Hour).Unix()
	good := s.sign(future)
	tampered := strings.Replace(good, strconv.FormatInt(future, 10), strconv.FormatInt(future+1, 10), 1)
	for name, tc := range map[string]struct {
		tok  string
		want bool
	}{
		"good": {good, true}, "expired": {s.sign(time.Now().Add(-time.Hour).Unix()), false},
		"tampered": {tampered, false}, "garbage": {"x", false}, "empty": {"", false},
	} {
		if got := s.valid(tc.tok); got != tc.want {
			t.Errorf("%s: valid = %v, want %v", name, got, tc.want)
		}
	}
}

// Saved positions must survive a restart, and a damaged file must not stop
// the server from starting.
func TestProgressFile(t *testing.T) {
	root, file := t.TempDir(), filepath.Join(t.TempDir(), "progress.json")
	start := func() (http.Handler, func(*http.Request)) {
		s, _ := newServer(root, "pw")
		s.load(file)
		h := s.routes()
		c := do(h, "POST", "/api/login", "pw", nil).Result().Cookies()[0]
		return h, func(r *http.Request) { r.AddCookie(c) }
	}
	h, authed := start() // no file yet
	do(h, "POST", "/api/progress", `{"p":"x/y.mp3","t":1234}`, authed)

	h, authed = start() // "restart"
	if body := do(h, "GET", "/api/progress", "", authed).Body.String(); !strings.Contains(body, `"x/y.mp3":{"t":1234,`) {
		t.Errorf("after restart progress = %s, want x/y.mp3 at 1234", body)
	}
	if _, err := os.Stat(file + ".tmp"); err == nil {
		t.Error("temporary file was left behind")
	}

	os.WriteFile(file, []byte("{half a fi"), 0o600)
	h, authed = start()
	if body := strings.TrimSpace(do(h, "GET", "/api/progress", "", authed).Body.String()); body != "{}" {
		t.Errorf("progress from a damaged file = %s, want {}", body)
	}
}

// The whole server through its HTTP routes, in the order a browser uses them:
// refused without login, login, index, media, positions, logout.
func TestFlow(t *testing.T) {
	h := testServer(t)

	if c := do(h, "GET", "/api/index", "", nil).Code; c != 401 {
		t.Errorf("index without cookie = %d, want 401", c)
	}
	if c := do(h, "GET", "/m/a/b.mp4", "", nil).Code; c != 401 {
		t.Errorf("media without cookie = %d, want 401", c)
	}
	if c := do(h, "POST", "/api/login", "wrong", nil).Code; c != 401 {
		t.Errorf("wrong password = %d, want 401", c)
	}
	if c := do(h, "GET", "/", "", func(r *http.Request) { r.RemoteAddr = "8.8.8.8:1" }).Code; c != 403 {
		t.Errorf("public IP = %d, want 403", c)
	}

	login := do(h, "POST", "/api/login", "pw", nil)
	cs := login.Result().Cookies()
	if login.Code != 200 || len(cs) != 1 {
		t.Fatalf("login = %d, cookies = %d", login.Code, len(cs))
	}
	if c := cs[0]; !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags wrong: %+v", c)
	}
	authed := func(r *http.Request) { r.AddCookie(cs[0]) }

	var got []entry
	idx := do(h, "GET", "/api/index", "", authed)
	if err := json.Unmarshal(idx.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].P != "a/b.mp4" || got[1].P != "f.MP3" || got[0].S != 10 {
		t.Errorf("index = %+v, want [a/b.mp4 f.MP3]", got)
	}

	if w := do(h, "GET", "/m/a/b.mp4", "", authed); w.Code != 200 || w.Header().Get("Content-Type") != "video/mp4" {
		t.Errorf("full media = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	w := do(h, "GET", "/m/a/b.mp4", "", func(r *http.Request) { authed(r); r.Header.Set("Range", "bytes=2-4") })
	if w.Code != 206 || w.Header().Get("Content-Range") != "bytes 2-4/10" || w.Body.String() != "234" {
		t.Errorf("range = %d %q %q", w.Code, w.Header().Get("Content-Range"), w.Body.String())
	}

	for _, p := range []string{
		"/m/a/c.txt", "/m/.hid/d.mp4", "/m/lost+found/e.mp3", "/m/nope.mp4", "/m/link.mp4", "/m/dirlink/b.mp4",
		"/m/../secret.mp4", "/m/..%2fsecret.mp4", "/m/%2e%2e/secret.mp4", "/m/a/..%2f..%2fsecret.mp4",
	} {
		if c := do(h, "GET", p, "", authed).Code; c == 200 {
			t.Errorf("GET %s = 200, want a refusal", p)
		}
	}

	// Playback positions: login required, save, read back, clear, bad input.
	if c := do(h, "GET", "/api/progress", "", nil).Code; c != 401 {
		t.Errorf("progress without cookie = %d, want 401", c)
	}
	if c := do(h, "POST", "/api/progress", `{"p":"a/b.mp4","t":90}`, nil).Code; c != 401 {
		t.Errorf("save progress without cookie = %d, want 401", c)
	}
	progress := func() map[string]pos {
		m := map[string]pos{}
		json.Unmarshal(do(h, "GET", "/api/progress", "", authed).Body.Bytes(), &m)
		return m
	}
	if c := do(h, "POST", "/api/progress", `{"p":"a/b.mp4","t":90.5}`, authed).Code; c != 204 {
		t.Errorf("save progress = %d, want 204", c)
	}
	if m := progress(); len(m) != 1 || m["a/b.mp4"].T != 90.5 || m["a/b.mp4"].At == 0 {
		t.Errorf("progress = %+v, want a/b.mp4 at 90.5", m)
	}
	for _, body := range []string{`{"p":"a/c.txt","t":5}`, `{"p":".hid/d.mp4","t":5}`, `{"p":"../secret.mp4","t":5}`, `{"p":"/a/b.mp4","t":5}`, `{"p":"a/b.mp4","t":"x"}`, `{"t":5}`, `nonsense`} {
		if c := do(h, "POST", "/api/progress", body, authed).Code; c != 400 {
			t.Errorf("save progress %s = %d, want 400", body, c)
		}
	}
	do(h, "POST", "/api/progress", `{"p":"a/b.mp4","t":0}`, authed)
	if m := progress(); len(m) != 0 {
		t.Errorf("progress after clearing = %+v, want empty", m)
	}

	out := do(h, "POST", "/api/logout", "", authed).Result().Cookies()
	if len(out) != 1 || out[0].Name != "hs" || out[0].Value != "" || out[0].MaxAge >= 0 {
		t.Errorf("logout cookies = %+v, want one empty, expired hs cookie", out)
	}
}
