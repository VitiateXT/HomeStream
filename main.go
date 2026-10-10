// HomeStream is a tiny media streamer for the home network. It serves the
// video and audio files found below one folder over HTTPS, behind a single
// password. It uses only the Go standard library.
//
// Routes:
//
//	GET  /           the web page (index.html), public
//	POST /api/login  checks the password and sets the session cookie
//	GET  /api/index  JSON list of all playable files, login required
//	GET  /m/<path>   one media file with Range support (seeking), login required
//
// Configuration is read from environment variables:
//
//	HS_PASSWORD  the login password (required)
//	HS_ROOT      media folder        (default ~/Media)
//	HS_ADDR      listen address      (default :8443)
//	HS_CERT      TLS certificate     (default ~/.config/homestream/cert.pem)
//	HS_KEY       TLS private key     (default ~/.config/homestream/key.pem)
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// indexHTML is the web page, compiled into the binary so that deploying
// HomeStream means copying a single file.
//
//go:embed index.html
var indexHTML []byte

// types lists the file extensions that are served and their Content-Type.
// Any other file (.txt, .part, ...) is invisible: it is neither listed nor
// downloadable. Add an extension here to serve a new format.
var types = map[string]string{
	".mp4": "video/mp4", ".m4v": "video/mp4", ".webm": "video/webm",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".flac": "audio/flac",
	".ogg": "audio/ogg", ".opus": "audio/ogg", ".wav": "audio/wav",
}

// sessionTTL is how long a login stays valid.
const sessionTTL = 30 * 24 * time.Hour

func init() {
	// Register the types explicitly so the Content-Type never depends on
	// the host's /etc/mime.types.
	for ext, t := range types {
		mime.AddExtensionType(ext, t)
	}
}

// entry is one file in the library index. The JSON keys are kept short
// because the index holds thousands of entries.
type entry struct {
	P string `json:"p"` // path relative to the media root, always with "/"
	S int64  `json:"s"` // size in bytes
}

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
	// mu serialises login attempts so that at most one guess per delay is
	// possible, however many connections an attacker opens.
	mu sync.Mutex
}

// newServer prepares a server for the media folder root and the given password.
func newServer(root, password string) (*server, error) {
	// filepath.WalkDir does not follow a symlinked root, and ~/Media is one
	// on this machine, so resolve it up front.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return nil, errors.New(root + " is not a directory")
	}
	s := &server{root: root, pwHash: sha256.Sum256([]byte(password)), secret: make([]byte, 32), delay: time.Second}
	_, err = rand.Read(s.secret)
	return s, err
}

// routes builds the request handler. Only the page and the login endpoint are
// public; everything that exposes file names or content goes through auth.
// The whole thing is wrapped in guard, which enforces the LAN-only rule.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("GET /api/index", s.auth(s.index))
	mux.HandleFunc("GET /m/{p...}", s.auth(s.media))
	return guard(mux)
}

// hidden reports whether a single path segment must never be listed or
// served: dotfiles and dot-folders (such as .Trash-1000) and lost+found.
func hidden(name string) bool { return strings.HasPrefix(name, ".") || name == "lost+found" }

// allowed reports whether a cleaned, slash-separated path relative to the
// media root may be listed and served. It is the single gatekeeper used by
// both the index and the file download, so a hidden file cannot be fetched
// by guessing its URL.
func allowed(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || hidden(seg) {
			return false
		}
	}
	_, ok := types[strings.ToLower(path.Ext(rel))]
	return ok
}

// isLAN reports whether a "host:port" client address is on the local network:
// loopback, private (10.x, 172.16-31.x, 192.168.x, fc00::/7) or link-local.
// Anything else, such as a public address, is refused.
func isLAN(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap() // treat ::ffff:192.168.1.5 like 192.168.1.5
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
}

// guard is the outermost handler. It rejects clients that are not on the LAN,
// as a second line of defense behind the firewall, and sets security headers.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLAN(r.RemoteAddr) {
			http.Error(w, "LAN only", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// sign returns a session token that expires at the Unix time exp. The token
// has the form "<exp>.<hex HMAC-SHA256 of exp>". It is stateless: the server
// stores nothing and only needs the secret to check a token later.
func (s *server) sign(exp int64) string {
	e := strconv.FormatInt(exp, 10)
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(e))
	return e + "." + hex.EncodeToString(m.Sum(nil))
}

// valid reports whether tok is a token made by sign that has not expired.
// It recomputes the token for the claimed expiry and compares in constant
// time, so a forged or edited token fails.
func (s *server) valid(tok string) bool {
	e, _, ok := strings.Cut(tok, ".")
	exp, err := strconv.ParseInt(e, 10, 64)
	if !ok || err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(tok), []byte(s.sign(exp)))
}

// auth wraps a handler so that it only runs for requests carrying a valid
// session cookie. Everyone else gets 401, which the web page reads as
// "show the login form".
func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("hs"); err != nil || !s.valid(c.Value) {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// login checks the password sent as the request body and, if it is right,
// sets the session cookie.
//
// The password is hashed first so the comparison always works on two
// fixed-length values and takes the same time for any input. The mutex is held
// while sleeping after a wrong password, which means failed attempts are
// handled one at a time. A correct login can therefore be delayed for a moment
// while wrong guesses are queued; that is the price of the rate limit.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	pw, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
	h := sha256.Sum256(pw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if subtle.ConstantTimeCompare(h[:], s.pwHash[:]) != 1 {
		time.Sleep(s.delay)
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return
	}
	// HttpOnly: scripts cannot read it. Secure: only sent over HTTPS.
	// SameSite=Lax: not sent on cross-site requests.
	http.SetCookie(w, &http.Cookie{
		Name: "hs", Value: s.sign(time.Now().Add(sessionTTL).Unix()), Path: "/",
		MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// index answers with the list of every servable file as JSON. It walks the
// media folder on each request, which is fast enough for thousands of files.
// The web page builds folders and search from this one flat list.
//
// Unreadable folders are skipped silently. Symlinks are not listed, because
// WalkDir does not follow them.
func (s *server) index(w http.ResponseWriter, r *http.Request) {
	out := []entry{}
	filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(s.root, p)
		if err != nil || rel == "." {
			return nil
		}
		if d.IsDir() && hidden(d.Name()) {
			return filepath.SkipDir // do not descend into .Trash-1000 etc.
		}
		rel = filepath.ToSlash(rel)
		if d.Type().IsRegular() && allowed(rel) {
			if fi, err := d.Info(); err == nil {
				out = append(out, entry{rel, fi.Size()})
			}
		}
		return nil
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}

// media sends one file from the media folder.
//
// http.ServeContent does the heavy lifting: it understands Range requests and
// answers them with 206 Partial Content, which is what lets a browser seek
// inside a film without downloading it all, and it sets Content-Length and
// Last-Modified. Files are never loaded into memory.
//
// Cleaning the path after a leading "/" removes every "..", so the request
// cannot climb out of the media folder. allowed then applies the same filter
// as the index.
func (s *server) media(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, "/m/")), "/")
	if !allowed(rel) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(s.root, filepath.FromSlash(rel)))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, rel, fi.ModTime(), f)
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
