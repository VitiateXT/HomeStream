// Who may use HomeStream: devices on the LAN, HomeStream's own page for
// anything that changes state, and the holder of a valid session cookie,
// which only the password gets.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// sessionTTL is how long a login stays valid.
const sessionTTL = 30 * 24 * time.Hour

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

// sameOrigin reports whether a request was made by HomeStream's own page.
// Browsers mark requests that another website or another web app on this PC
// makes on the visitor's behalf: with Sec-Fetch-Site, or in older browsers
// with Origin. Requests from tools such as curl carry neither and pass; they
// do not run in the visitor's logged-in browser.
func sameOrigin(r *http.Request) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" {
		return s == "same-origin"
	}
	o := r.Header.Get("Origin")
	return o == "" || o == "https://"+r.Host
}

// guard is the outermost handler. It rejects clients that are not on the LAN,
// as a second line of defense behind the firewall, and tells browsers not to
// guess content types.
//
// Every POST (login, logout, saving a position) must come from HomeStream's
// own page. Otherwise a website the visitor opens could use their browser,
// which is on the LAN, to guess the password (a wrong one takes a second, the
// right one does not) or to act with their login. Its body must also arrive
// within 10 seconds, so a client cannot hold a connection open forever by
// sending it slowly.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLAN(r.RemoteAddr) {
			http.Error(w, "LAN only", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodPost {
			if !sameOrigin(r) {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
			http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second))
		}
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

// cookie is the session cookie with the given value, kept for maxAge
// seconds; -1 deletes it. HttpOnly: scripts cannot read it. Secure: only sent
// over HTTPS. SameSite=Lax: not sent on cross-site requests.
func cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: "hs", Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
}

// login checks the password sent as the request body and, if it is right,
// sets the session cookie.
//
// The password is hashed first so the comparison always works on two
// fixed-length values and takes the same time for any input. loginMu is held
// while sleeping after a wrong password, which means failed attempts are
// handled one at a time. A correct login can therefore be delayed for a moment
// while wrong guesses are queued; that is the price of the rate limit. A body
// that does not arrive in full is refused at once instead of joining the
// queue. Wrong passwords are logged with the client's address, at most one a
// second because of the lock.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	pw, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	h := sha256.Sum256(pw)
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if subtle.ConstantTimeCompare(h[:], s.pwHash[:]) != 1 {
		log.Printf("wrong password from %s", r.RemoteAddr)
		time.Sleep(s.delay)
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, cookie(s.sign(time.Now().Add(sessionTTL).Unix()), int(sessionTTL.Seconds())))
}

// logout deletes the session cookie in the browser that asks.
//
// Sessions are stateless, so the server cannot cancel a token: a copy of the
// cookie kept elsewhere stays valid until it expires. Restarting the server
// ends every session.
func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, cookie("", -1))
}
