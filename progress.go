// Saved playback positions, shared by all devices.

package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// pos is the saved playback position of one file.
type pos struct {
	T  float64 `json:"t"`  // seconds from the start
	At int64   `json:"at"` // Unix time of the save, orders the Continue list
}

// positions holds the saved position of every started file, keyed by its
// path. There is one password and so one user: all devices share them.
type positions struct {
	// mu guards m. It is separate from loginMu, which is held for a whole
	// second after a wrong password and must not hold up saving.
	mu sync.Mutex
	m  map[string]pos
	// file is where m is saved. Empty means memory only.
	file string
}

// load reads the saved positions from file and remembers it as the place to
// save later changes. A missing file is normal on first start. An unreadable
// one is logged and replaced by the next save.
func (ps *positions) load(file string) {
	ps.file = file
	b, err := os.ReadFile(file)
	if err != nil {
		return
	}
	if err := json.Unmarshal(b, &ps.m); err != nil {
		log.Printf("ignoring unreadable %s: %v", file, err)
		ps.m = map[string]pos{}
	}
	if ps.m == nil { // the file held "null"
		ps.m = map[string]pos{}
	}
}

// json returns all positions as JSON.
func (ps *positions) json() []byte {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	b, _ := json.Marshal(ps.m)
	return b
}

// set stores the position t of the file p, or forgets it if t is zero or
// less, and saves the change.
//
// The whole map is written to a temporary file and renamed over the real one.
// A rename is atomic, so a crash never leaves a half-written file. The map is
// small and a playing device saves every ten seconds, so this is cheap.
func (ps *positions) set(p string, t float64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if t <= 0 {
		delete(ps.m, p)
	} else {
		ps.m[p] = pos{t, time.Now().Unix()}
	}
	if ps.file == "" {
		return
	}
	b, _ := json.Marshal(ps.m)
	err := os.WriteFile(ps.file+".tmp", b, 0o600)
	if err == nil {
		err = os.Rename(ps.file+".tmp", ps.file)
	}
	if err != nil {
		log.Print(err)
	}
}

// progress answers with every saved playback position as JSON. The lock is
// released before sending, so a device that stalls while downloading cannot
// hold up saving for everyone else.
func (s *server) progress(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, s.pos.json())
}

// saveProgress stores the position sent as {"p": path, "t": seconds}. A t of
// zero or less forgets the file, which is how a finished one is cleared.
// allowed only accepts a clean media path, so nothing else can become a key.
func (s *server) saveProgress(w http.ResponseWriter, r *http.Request) {
	var in struct {
		P string  `json:"p"`
		T float64 `json:"t"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil || !allowed(in.P) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.pos.set(in.P, in.T)
	w.WriteHeader(http.StatusNoContent)
}
