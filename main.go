// HomeStream is a tiny media streamer for the home network. It serves the
// videos, music, PDFs and images found below one folder over HTTPS, behind a
// single password. It uses only the Go standard library, plus ffmpeg (if
// installed) to make video thumbnails.
//
// Routes:
//
//	GET  /              the web page (index.html), public
//	POST /api/login     checks the password and sets the session cookie
//	POST /api/logout    deletes the session cookie
//	GET  /api/index     JSON list of all servable files, login required
//	GET  /api/progress  saved playback positions, login required
//	POST /api/progress  saves the position of one file, login required
//	GET  /m/<path>      one file with Range support (seeking), login required
//	GET  /t/<path>      a small JPEG thumbnail of one video, login required
//
// Configuration is read from environment variables:
//
//	HS_PASSWORD  the login password (required)
//	HS_ROOT      media folder        (default ~/Media)
//	HS_ADDR      listen address      (default :8443)
//	HS_CERT      TLS certificate     (default ~/.config/homestream/cert.pem)
//	HS_KEY       TLS private key     (default ~/.config/homestream/key.pem)
//	HS_PROGRESS  saved positions     (default ~/.config/homestream/progress.json)
//
// Thumbnails are kept in ~/.cache/homestream/thumbs.
//
// The code is split by job:
//
//	main.go      configuration, the server type and the routes
//	auth.go      LAN check, password, session cookie
//	library.go   which files exist and may be served, the index, the files
//	progress.go  saved playback positions
//	thumbs.go    video thumbnails
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// indexHTML is the web page, compiled into the binary so that deploying
// HomeStream means copying a single file.
//
//go:embed index.html
var indexHTML []byte

// server holds the state shared by all request handlers.
type server struct {
	// root is the media folder with symlinks resolved.
	root string
	// pwHash is the SHA-256 of the password. Login compares hashes (always 32
	// bytes) in constant time instead of comparing the passwords themselves.
	pwHash [32]byte
	// secret signs the session cookies. It is random on every start, so a
	// restart logs everyone out.
	secret []byte
	// delay is the pause after a wrong password.
	delay time.Duration
	// loginMu serialises login attempts so that at most one guess per delay
	// is possible, however many connections an attacker opens.
	loginMu sync.Mutex
	// pos holds the saved playback positions.
	pos positions
	// thumbs is the folder thumbnails are cached in. Empty means none are made.
	thumbs string
	// busy limits how many thumbnails are made at the same time.
	busy chan struct{}
}

// newServer prepares a server for the media folder root and the given password.
func newServer(root, password string) (*server, error) {
	// The media folder may itself be a symlink. filepath.WalkDir would not
	// follow it, so resolve it up front.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return nil, errors.New(root + " is not a directory")
	}
	s := &server{
		root: root, pwHash: sha256.Sum256([]byte(password)), secret: make([]byte, 32), delay: time.Second,
		pos: positions{m: map[string]pos{}}, busy: make(chan struct{}, 8),
	}
	_, err = rand.Read(s.secret)
	return s, err
}

// routes builds the request handler. Only the page, login and logout are
// public; everything that exposes file names or content goes through auth.
// The whole thing is wrapped in guard, which enforces the LAN-only rule.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", logout)
	mux.HandleFunc("GET /api/index", s.auth(s.index))
	mux.HandleFunc("GET /api/progress", s.auth(s.progress))
	mux.HandleFunc("POST /api/progress", s.auth(s.saveProgress))
	mux.HandleFunc("GET /m/{p...}", s.auth(s.media))
	mux.HandleFunc("GET /t/{p...}", s.auth(s.thumb))
	return guard(mux)
}

// sendJSON answers with b, which is already JSON. no-store makes browsers
// ask again every time, so they never show a stale list or position.
func sendJSON(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// env returns the environment variable key, or def if it is unset or empty.
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// main reads the configuration and starts the HTTPS server.
func main() {
	pw := os.Getenv("HS_PASSWORD")
	if pw == "" {
		log.Fatal("HS_PASSWORD is required")
	}
	home, _ := os.UserHomeDir()
	cfg := filepath.Join(home, ".config", "homestream")
	s, err := newServer(env("HS_ROOT", filepath.Join(home, "Media")), pw)
	if err != nil {
		log.Fatal(err)
	}
	s.pos.load(env("HS_PROGRESS", filepath.Join(cfg, "progress.json")))
	s.thumbs = thumbDir()
	// There is deliberately no WriteTimeout: a film takes hours to play and
	// the response must stay open for as long as the viewer keeps watching.
	srv := &http.Server{
		Addr:              env("HS_ADDR", ":8443"),
		Handler:           s.routes(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("serving %s on https://%s", s.root, srv.Addr)
	log.Fatal(srv.ListenAndServeTLS(env("HS_CERT", filepath.Join(cfg, "cert.pem")), env("HS_KEY", filepath.Join(cfg, "key.pem"))))
}
