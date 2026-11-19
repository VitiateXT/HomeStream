package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Which paths may be listed and served.
func TestAllowed(t *testing.T) {
	for rel, want := range map[string]bool{
		"Films/300.mp4": true, "a/b.MP3": true, "a/b [x].opus": true,
		"a/b.txt": false, "a/b.mp4.part": false, ".Trash-1000/x.mp4": false,
		"a/.hid/x.mp4": false, "lost+found/x.mp3": false, "": false, "a//b.mp4": false,
		"a/...title.mp4": true, "a/._junk.mp4": false, "../x.mp4": false, "/a/b.mp4": false,
		"Books/a.pdf": true, "p/x.JPG": true, "p/x.webp": true, "p/x.svg": false, "p/x.heic": false,
		".mp4": false, "a/.mp4": false,
	} {
		if got := allowed(rel); got != want {
			t.Errorf("allowed(%q) = %v, want %v", rel, got, want)
		}
	}
}

// library makes a media folder with a file in it, a file just outside it and
// a symlink inside pointing out, and returns a server for it.
func library(t testing.TB) *server {
	root := filepath.Join(t.TempDir(), "lib")
	os.MkdirAll(filepath.Join(root, "a"), 0o755)
	for _, p := range []string{"a/b.mp4", "../secret.mp4"} {
		os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644)
	}
	os.Symlink(filepath.Join(root, "../secret.mp4"), filepath.Join(root, "a/link.mp4"))
	s, err := newServer(root, "pw")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// How the part of a URL after /m/ or /t/ becomes a file.
func TestResolve(t *testing.T) {
	s := library(t)
	for p, want := range map[string]string{
		"a/b.mp4": "a/b.mp4", "/a/b.mp4": "a/b.mp4", "a//b.mp4": "a/b.mp4", "a/./b.mp4": "a/b.mp4",
		"x/../a/b.mp4": "a/b.mp4", "../a/b.mp4": "a/b.mp4", // ".." cannot climb above the root
		"../secret.mp4": "", "a/../../secret.mp4": "", "a/link.mp4": "", "a/nope.mp4": "", "a": "", "": "",
	} {
		rel, full, ok := s.resolve(p)
		if rel != want || ok != (want != "") || ok && full != filepath.Join(s.root, want) {
			t.Errorf("resolve(%q) = %q %q %v, want %q", p, rel, full, ok, want)
		}
	}
}

// Whatever the path, resolve never gives a file outside the media folder or
// one that allowed refuses. Run longer with: go test -fuzz FuzzResolve
func FuzzResolve(f *testing.F) {
	for _, p := range []string{"a/b.mp4", "../secret.mp4", "a/../../secret.mp4", "a/link.mp4", "/a/b.mp4", "a\\..\\..\\secret.mp4", "a/b.mp4\x00", "....//secret.mp4"} {
		f.Add(p)
	}
	s := library(f)
	f.Fuzz(func(t *testing.T, p string) {
		rel, full, ok := s.resolve(p)
		if ok && (!strings.HasPrefix(full, s.root+string(filepath.Separator)) || !allowed(rel) || full != filepath.Join(s.root, rel)) {
			t.Errorf("resolve(%q) = %q %q, outside the media folder or not allowed", p, rel, full)
		}
	})
}
