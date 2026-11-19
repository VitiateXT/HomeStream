package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Saved positions must survive a restart, be readable only by the owner, and
// a damaged file must not stop the server from starting.
func TestProgressFile(t *testing.T) {
	root, file := t.TempDir(), filepath.Join(t.TempDir(), "progress.json")
	start := func() (http.Handler, func(*http.Request)) {
		s, _ := newServer(root, "pw")
		s.pos.load(file)
		h := s.routes()
		return h, loggedIn(t, h)
	}
	h, authed := start() // no file yet
	do(h, "POST", "/api/progress", `{"p":"x/y.mp3","t":1234}`, authed)

	h, authed = start() // "restart"
	if body := do(h, "GET", "/api/progress", "", authed).Body.String(); !strings.Contains(body, `"x/y.mp3":{"t":1234,`) {
		t.Errorf("after restart progress = %s, want x/y.mp3 at 1234", body)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("progress file mode = %v, %v, want 0600", fi.Mode().Perm(), err)
	}
	if _, err := os.Stat(file + ".tmp"); err == nil {
		t.Error("temporary file was left behind")
	}

	os.WriteFile(file, []byte("{half a fi"), 0o600)
	h, authed = start()
	if body := do(h, "GET", "/api/progress", "", authed).Body.String(); body != "{}" {
		t.Errorf("progress from a damaged file = %s, want {}", body)
	}
	os.WriteFile(file, []byte("null"), 0o600)
	h, authed = start()
	do(h, "POST", "/api/progress", `{"p":"x/y.mp3","t":5}`, authed) // must not panic on a nil map
	if body := do(h, "GET", "/api/progress", "", authed).Body.String(); !strings.Contains(body, `"x/y.mp3"`) {
		t.Errorf("progress after a null file = %s, want x/y.mp3", body)
	}
}

// stalledWriter is a client that stops reading as soon as an answer starts.
type stalledWriter struct{ started, release chan struct{} }

func (s stalledWriter) Header() http.Header { return http.Header{} }
func (s stalledWriter) WriteHeader(int)     {}
func (s stalledWriter) Write(b []byte) (int, error) {
	s.started <- struct{}{}
	<-s.release
	return len(b), nil
}

// A device that stalls while downloading the positions must not stop the
// other devices from saving.
func TestStalledReader(t *testing.T) {
	s, _ := newServer(t.TempDir(), "pw")
	w := stalledWriter{make(chan struct{}), make(chan struct{})}
	defer close(w.release)
	go s.progress(w, httptest.NewRequest("GET", "/api/progress", nil))
	<-w.started
	saved := make(chan struct{})
	go func() {
		s.saveProgress(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/progress", strings.NewReader(`{"p":"a/b.mp4","t":90}`)))
		close(saved)
	}()
	select {
	case <-saved:
	case <-time.After(2 * time.Second):
		t.Fatal("saving waits for a stalled reader")
	}
}
