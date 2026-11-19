package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Thumbnails: login required, the same refusals as for media, made once with
// ffmpeg and then served from the cache, and made again for a changed video.
// A broken video, or many devices asking at once, leave nothing behind.
func TestThumb(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "a/.hid"), 0o755)
	for _, p := range []string{"a/broken.mp4", "a/song.mp3", "a/.hid/x.mp4"} {
		os.WriteFile(filepath.Join(root, p), []byte("0123456789"), 0o644)
	}
	s, _ := newServer(root, "pw")
	s.thumbs = t.TempDir()
	h := s.routes()
	authed := loggedIn(t, h)

	if code := do(h, "GET", "/t/a/broken.mp4", "", nil).Code; code != 401 {
		t.Errorf("thumbnail without cookie = %d, want 401", code)
	}
	for _, p := range []string{"/t/a/song.mp3", "/t/a/.hid/x.mp4", "/t/../x.mp4", "/t/%2e%2e/x.mp4", "/t/a/nope.mp4", "/t/a/broken.mp4"} {
		if code := do(h, "GET", p, "", authed).Code; code == 200 {
			t.Errorf("GET %s = 200, want a refusal", p)
		}
	}
	cache := func() []string { m, _ := filepath.Glob(filepath.Join(s.thumbs, "*")); return m }
	if m := cache(); len(m) != 0 {
		t.Errorf("cache after refusals holds %v, want nothing", m)
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg is not installed")
	}
	video := filepath.Join(root, "a/v.mp4")
	if err := exec.Command("ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc=d=2:s=320x240", "-pix_fmt", "yuv420p", video).Run(); err != nil {
		t.Fatal(err)
	}
	get := func() {
		w := do(h, "GET", "/t/a/v.mp4", "", authed)
		if w.Code != 200 || w.Header().Get("Content-Type") != "image/jpeg" || !bytes.HasPrefix(w.Body.Bytes(), []byte{0xff, 0xd8}) {
			t.Errorf("thumbnail = %d %q", w.Code, w.Header().Get("Content-Type"))
		}
	}
	// Several devices at once, while it is still being made.
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); get() }()
	}
	wg.Wait()
	get() // from the cache
	if m := cache(); len(m) != 1 {
		t.Errorf("cache holds %v, want just one thumbnail", m)
	}
	later := time.Now().Add(time.Hour)
	os.Chtimes(video, later, later) // the video was replaced
	get()
	if m := cache(); len(m) != 2 {
		t.Errorf("cache after a change holds %v, want two thumbnails", m)
	}
}

// A request that waits for a free ffmpeg slot is dropped once its page has
// moved on, without running ffmpeg.
func TestThumbDropped(t *testing.T) {
	s, _ := newServer(t.TempDir(), "pw")
	for i := 0; i < cap(s.busy); i++ {
		s.busy <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	jpg := filepath.Join(t.TempDir(), "x.jpg")
	if s.makeThumb(ctx, "/nonexistent.mp4", jpg) {
		t.Error("makeThumb with every slot busy and the page gone = true, want false")
	}
}
