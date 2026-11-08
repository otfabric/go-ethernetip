// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest is testdata/captures/manifest.json: the sources of the recorded
// traffic and, per file, where it came from, its checksum, its evidence
// class and how this repository holds it.
type Manifest struct {
	Schema   int               `json:"schema"`
	Acquired string            `json:"acquired"`
	Classes  map[string]string `json:"classes"`
	Sources  []Source          `json:"sources"`
	Files    []File            `json:"files"`
}

// Source is one origin of captures.
type Source struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Revision       string `json:"revision"`
	Licence        string `json:"licence"`
	Redistribution string `json:"redistribution"`
}

// File is one capture file.
type File struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Path     string `json:"path"` // in the source
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Recorded string `json:"recorded"`
	// Class is the evidence class (A to D, see Manifest.Classes).
	Class string `json:"class"`
	// Storage is "raw" (committed byte-identical at Local) or "excerpt"
	// (Local is the excerpt; the raw file is fetched into the cache).
	Storage     string   `json:"storage"`
	Local       string   `json:"local"`
	MaxPerKind  int      `json:"maxPerKind,omitempty"`
	Devices     []string `json:"devices"`
	Peers       []string `json:"peers"`
	Operations  []string `json:"operations"`
	Limitations string   `json:"limitations"`
}

// CacheDir is where `make captures-fetch` puts the raw files of excerpts,
// relative to testdata/captures.
const CacheDir = ".cache"

// CachePath returns the path of the raw file in the cache, relative to
// testdata/captures.
func (f File) CachePath() string { return filepath.Join(CacheDir, f.Source, filepath.Base(f.Path)) }

// ReadManifest reads manifest.json from the captures directory dir.
func ReadManifest(dir string) (Manifest, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Manifest{}, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile("manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("capture: manifest: %w", err)
	}
	return m, nil
}

// Recording is one file of the corpus, read into conversations.
type Recording struct {
	File          File
	Conversations []Conversation
	// Excerpt is true when the conversations come from the committed
	// excerpt, not from the raw file.
	Excerpt bool
}

// Load reads the corpus in the captures directory dir: the committed raw
// files and, for the others, the committed excerpts, or with raw the raw
// files in the cache (`make captures-fetch`).
func Load(dir string, raw bool) ([]Recording, error) {
	m, err := ReadManifest(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Recording, 0, len(m.Files))
	for _, f := range m.Files {
		r := Recording{File: f}
		switch {
		case f.Storage == "raw":
			r.Conversations, err = ReadFile(filepath.Join(dir, f.Local))
		case raw:
			r.Conversations, err = ReadFile(filepath.Join(dir, f.CachePath()))
		default:
			var e Excerpt
			if e, err = ReadExcerpt(filepath.Join(dir, f.Local)); err == nil {
				r.Conversations, err = e.ToConversations()
				r.Excerpt = true
			}
		}
		if err != nil {
			return nil, fmt.Errorf("capture: %s: %w", f.ID, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Get returns the recording of the file with manifest ID id.
func Get(recs []Recording, id string) (Recording, bool) {
	for _, r := range recs {
		if r.File.ID == id {
			return r, true
		}
	}
	return Recording{}, false
}

// Frame returns the message that frame n completed, and its conversation.
func (r Recording) Frame(n int) (Conversation, Message, bool) {
	for _, c := range r.Conversations {
		for _, m := range c.Messages {
			if m.Frame == n {
				return c, m, true
			}
		}
	}
	return Conversation{}, Message{}, false
}

// Exchange returns the exchange whose request frame n completed.
func (r Recording) Exchange(n int) (Exchange, bool) {
	for _, c := range r.Conversations {
		if c.Transport != TCP {
			continue
		}
		ex, _ := Exchanges(c)
		for _, e := range ex {
			if e.Request.Frame == n {
				return e, true
			}
		}
	}
	return Exchange{}, false
}
