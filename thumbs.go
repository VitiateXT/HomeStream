// Video thumbnails, made with ffmpeg and kept in a cache folder.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// videos lists the extensions that get a thumbnail.
var videos = map[string]bool{".mp4": true, ".m4v": true, ".webm": true}

// thumbDir returns the folder to keep thumbnails in, creating it, or "" if
// there will be none: without ffmpeg, or without a cache folder, videos keep
// their colored tiles.
func thumbDir() string {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		log.Print("ffmpeg not found, so videos get no thumbnails")
		return ""
	}
	c, err := os.UserCacheDir()
	if err != nil {
		log.Print(err)
		return ""
	}
	dir := filepath.Join(c, "homestream", "thumbs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Print(err)
		return ""
	}
	return dir
}

// thumb sends a small JPEG of the frame 10% into a video. It is made on first
// request and then kept in the thumbs folder, named after the video's path,
// size and modification time, so a changed video gets a new one. Anything
// that goes wrong (no ffmpeg, a broken video) answers 404, and the page keeps
// its colored tile instead.
func (s *server) thumb(w http.ResponseWriter, r *http.Request) {
	rel, full, ok := s.resolve(strings.TrimPrefix(r.URL.Path, "/t/"))
	if !ok || s.thumbs == "" || !videos[strings.ToLower(path.Ext(rel))] {
		http.NotFound(w, r)
		return
	}
	fi, err := os.Stat(full)
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	key := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d", rel, fi.Size(), fi.ModTime().UnixNano())))
	jpg := filepath.Join(s.thumbs, hex.EncodeToString(key[:16])+".jpg")
	if _, err := os.Stat(jpg); err != nil && !s.makeThumb(r.Context(), full, jpg) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "private, max-age=604800")
	serveFile(w, r, jpg, "thumb.jpg")
}

// makeThumb runs ffmpeg to save one frame of video as jpg, 480 pixels wide.
// At most cap(busy) run at once; a request whose page has moved on while it
// waits is dropped. It writes a temporary file and renames it, so a cut-off
// run never leaves half a thumbnail behind. Each run has its own temporary
// file, so two devices asking for the same new thumbnail do not get in each
// other's way.
func (s *server) makeThumb(ctx context.Context, video, jpg string) bool {
	select {
	case s.busy <- struct{}{}:
		defer func() { <-s.busy }()
	case <-ctx.Done():
		return false
	}
	if _, err := os.Stat(jpg); err == nil {
		return true // made by another request while this one waited
	}
	page := ctx
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// The length, to pick a frame past any black opening. Unknown: the first.
	out, _ := exec.CommandContext(ctx, "ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", video).Output()
	d, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	f, err := os.CreateTemp(filepath.Dir(jpg), "*.tmp")
	if err != nil {
		log.Print(err)
		return false
	}
	f.Close()
	tmp := f.Name()
	err = exec.CommandContext(ctx, "ffmpeg", "-nostdin", "-v", "error", "-ss", strconv.FormatFloat(d/10, 'f', 2, 64), "-i", video,
		"-frames:v", "1", "-vf", "scale=480:-2", "-q:v", "5", "-f", "image2", "-y", tmp).Run()
	if err == nil {
		err = os.Rename(tmp, jpg)
	}
	if err != nil {
		os.Remove(tmp)
		if page.Err() == nil { // not when the page simply moved on
			log.Printf("no thumbnail for %s: %v", video, err)
		}
	}
	return err == nil
}
