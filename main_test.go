package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

// testServer returns a server over a small library that holds one of each
// case: playable files, a PDF, a text file, a hidden folder, lost+found and
// symlinks.
func testServer(t *testing.T) http.Handler {
	// The media root is a subfolder, so that ../secret.mp4 is a real media file
	// just outside it: the only thing keeping it private is the ".." handling.
	root := filepath.Join(t.TempDir(), "lib")
	for _, p := range []string{"a/b.mp4", "a/c.txt", "a/d.pdf", ".hid/d.mp4", "lost+found/e.mp3", "f.MP3", "../secret.mp4"} {
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

// loggedIn logs in with the password "pw" and returns a mod for do that adds
// the session cookie.
func loggedIn(t *testing.T, h http.Handler) func(*http.Request) {
	cs := do(h, "POST", "/api/login", "pw", nil).Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("login gave %d cookies, want 1", len(cs))
	}
	return func(r *http.Request) { r.AddCookie(cs[0]) }
}

// The media folder must be a folder, and may be a symlink to one (as
// ~/Media -> /mnt/media is).
func TestNewServer(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file"), nil, 0o644)
	os.Mkdir(filepath.Join(dir, "real"), 0o755)
	os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link"))
	for _, root := range []string{filepath.Join(dir, "nope"), filepath.Join(dir, "file")} {
		if _, err := newServer(root, "pw"); err == nil {
			t.Errorf("newServer(%s) worked, want an error", root)
		}
	}
	s, err := newServer(filepath.Join(dir, "link"), "pw")
	if err != nil || s.root != filepath.Join(dir, "real") {
		t.Errorf("newServer(link) = %v, %v, want root %s", s, err, filepath.Join(dir, "real"))
	}
	t.Setenv("HS_TEST", "")
	if env("HS_TEST", "def") != "def" {
		t.Error("env with an empty variable did not use the default")
	}
	t.Setenv("HS_TEST", "x")
	if env("HS_TEST", "def") != "x" {
		t.Error("env did not use the variable")
	}
}

// The page is public and the only thing served at the top level.
func TestPage(t *testing.T) {
	h := testServer(t)
	w := do(h, "GET", "/", "", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(w.Body.String(), "<title>HomeStream</title>") {
		t.Errorf("page = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff header missing")
	}
	if w := do(h, "GET", "/logo.png", "", nil); w.Code != 200 || w.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(w.Body.Bytes(), []byte("\x89PNG")) {
		t.Errorf("logo = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	for _, p := range []string{"/logo.aseprite", "/index.html", "/main.go", "/api/", "/m/", "/x"} {
		if c := do(h, "GET", p, "", nil).Code; c != 404 && c != 401 {
			t.Errorf("GET %s = %d, want 404 or 401", p, c)
		}
	}
	if c := do(h, "DELETE", "/api/progress", "", nil).Code; c != 405 {
		t.Errorf("DELETE /api/progress = %d, want 405", c)
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
	// POSTs marked by the browser as coming from another website or another
	// app on this PC are refused, even with the right password. HomeStream's
	// own page and tools without these headers pass.
	for _, tc := range []struct {
		hdr, val string
		want     int
	}{
		{"Sec-Fetch-Site", "cross-site", 403}, {"Sec-Fetch-Site", "same-site", 403}, {"Origin", "https://evil.example", 403},
		{"Origin", "null", 403}, {"Sec-Fetch-Site", "same-origin", 200}, {"Origin", "https://example.com", 200}, {"", "", 200},
	} {
		if c := do(h, "POST", "/api/login", "pw", func(r *http.Request) { r.Header.Set(tc.hdr, tc.val) }).Code; c != tc.want {
			t.Errorf("login with %s %q = %d, want %d", tc.hdr, tc.val, c, tc.want)
		}
	}
	if c := do(h, "POST", "/api/login", "", func(r *http.Request) { r.Body = io.NopCloser(iotest.ErrReader(io.ErrUnexpectedEOF)) }).Code; c != 400 {
		t.Errorf("login with a broken body = %d, want 400", c)
	}

	login := do(h, "POST", "/api/login", "pw", nil)
	cs := login.Result().Cookies()
	if login.Code != 200 || len(cs) != 1 {
		t.Fatalf("login = %d, cookies = %d", login.Code, len(cs))
	}
	if c := cs[0]; !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge != int(sessionTTL.Seconds()) {
		t.Errorf("cookie flags wrong: %+v", c)
	}
	authed := func(r *http.Request) { r.AddCookie(cs[0]) }

	var got []entry
	idx := do(h, "GET", "/api/index", "", authed)
	if err := json.Unmarshal(idx.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].P != "a/b.mp4" || got[1].P != "a/d.pdf" || got[2].P != "f.MP3" || got[0].S != 10 {
		t.Errorf("index = %+v, want [a/b.mp4 a/d.pdf f.MP3]", got)
	}
	if idx.Header().Get("Content-Type") != "application/json" || idx.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("index headers = %v", idx.Header())
	}

	if w := do(h, "GET", "/m/a/b.mp4", "", authed); w.Code != 200 || w.Header().Get("Content-Type") != "video/mp4" {
		t.Errorf("full media = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	w := do(h, "GET", "/m/a/b.mp4", "", func(r *http.Request) { authed(r); r.Header.Set("Range", "bytes=2-4") })
	if w.Code != 206 || w.Header().Get("Content-Range") != "bytes 2-4/10" || w.Body.String() != "234" {
		t.Errorf("range = %d %q %q", w.Code, w.Header().Get("Content-Range"), w.Body.String())
	}
	w = do(h, "GET", "/m/a/d.pdf", "", func(r *http.Request) { authed(r); r.Header.Set("Range", "bytes=0-3") })
	if w.Code != 206 || w.Header().Get("Content-Type") != "application/pdf" {
		t.Errorf("pdf range = %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w := do(h, "GET", "/m/f.MP3", "", authed); w.Code != 200 || w.Header().Get("Content-Type") != "audio/mpeg" {
		t.Errorf("upper-case extension = %d %q", w.Code, w.Header().Get("Content-Type"))
	}

	for _, p := range []string{
		"/m/a/c.txt", "/m/.hid/d.mp4", "/m/lost+found/e.mp3", "/m/nope.mp4", "/m/link.mp4", "/m/dirlink/b.mp4",
		"/m/../secret.mp4", "/m/..%2fsecret.mp4", "/m/%2e%2e/secret.mp4", "/m/a/..%2f..%2fsecret.mp4", "/m/a",
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
	if c := do(h, "POST", "/api/progress", `{"p":"a/b.mp4","t":90.5}`, func(r *http.Request) { authed(r); r.Header.Set("Sec-Fetch-Site", "same-site") }).Code; c != 403 {
		t.Errorf("save progress from another app on this PC = %d, want 403", c)
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
	if len(out) != 1 || out[0].Name != "hs" || out[0].Value != "" || out[0].MaxAge >= 0 || !out[0].Secure || !out[0].HttpOnly {
		t.Errorf("logout cookies = %+v, want one empty, expired hs cookie", out)
	}
}
