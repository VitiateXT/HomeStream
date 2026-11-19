// The media library: which files may be listed and served, the list of
// them, and sending one.

package main

import (
	"encoding/json"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// types lists the file extensions that are served and their Content-Type.
// Any other file (.txt, .part, ...) is invisible: it is neither listed nor
// downloadable. To serve a new format, add it here and to kind() in
// index.html, which decides how a file is shown. SVG is left out on purpose:
// an SVG can carry scripts, which would run as part of this site.
var types = map[string]string{
	".mp4": "video/mp4", ".m4v": "video/mp4", ".webm": "video/webm",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".flac": "audio/flac",
	".ogg": "audio/ogg", ".opus": "audio/ogg", ".wav": "audio/wav",
	".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg",
	".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
}

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

// hidden reports whether a single path segment must never be listed or
// served: dotfiles and dot-folders (such as .Trash-1000) and lost+found.
// A name starting with "..." is an ordinary title, not a hidden file.
func hidden(name string) bool {
	return strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "...") || name == "lost+found"
}

// allowed reports whether a cleaned, slash-separated path relative to the
// media root may be listed and served. It is the single gatekeeper used by
// the index, the files, the thumbnails and the saved positions, so a hidden
// file cannot be fetched by guessing its URL.
func allowed(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || hidden(seg) {
			return false
		}
	}
	_, ok := types[strings.ToLower(path.Ext(rel))]
	return ok
}

// resolve turns the part of a URL after /m/ or /t/ into a file in the media
// folder: its path relative to the root and its full path. ok is false if it
// may not be served.
//
// Cleaning the path after a leading "/" removes every "..", so the request
// cannot climb out of the media folder. allowed then applies the same filter
// as the index, and symlinks are refused: EvalSymlinks returns the path
// unchanged unless a symlink is involved, and a link named x.mp4 could point
// at any file outside the media folder.
func (s *server) resolve(p string) (rel, full string, ok bool) {
	rel = strings.TrimPrefix(path.Clean("/"+p), "/")
	if !allowed(rel) {
		return "", "", false
	}
	full = filepath.Join(s.root, filepath.FromSlash(rel))
	if p, err := filepath.EvalSymlinks(full); err != nil || p != full {
		return "", "", false
	}
	return rel, full, true
}

// index answers with the list of every servable file as JSON. It walks the
// media folder on each request, which is fast enough for thousands of files.
// The web page builds folders and search from this one flat list.
//
// Unreadable folders are skipped silently. Symlinks are not listed: WalkDir
// does not follow linked folders, and linked files are not regular files.
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
	b, _ := json.Marshal(out)
	sendJSON(w, b)
}

// media sends one file from the media folder.
func (s *server) media(w http.ResponseWriter, r *http.Request) {
	rel, full, ok := s.resolve(strings.TrimPrefix(r.URL.Path, "/m/"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	serveFile(w, r, full, rel)
}

// serveFile sends the regular file at full, under the name name (whose
// extension sets the Content-Type), or answers 404.
//
// http.ServeContent does the heavy lifting: it understands Range requests and
// answers them with 206 Partial Content, which is what lets a browser seek
// inside a film without downloading it all, and it sets Content-Length and
// Last-Modified. Files are never loaded into memory.
func serveFile(w http.ResponseWriter, r *http.Request, full, name string) {
	f, err := os.Open(full)
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
	http.ServeContent(w, r, name, fi.ModTime(), f)
}
